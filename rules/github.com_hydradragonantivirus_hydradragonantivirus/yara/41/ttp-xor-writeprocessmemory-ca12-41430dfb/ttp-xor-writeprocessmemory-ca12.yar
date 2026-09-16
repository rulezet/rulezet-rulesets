rule TTP_XOR_WriteProcessMemory_ca12 {
  strings:
    $key_ca12 = { 9d 60 [2] af 42 [2] a9 77 [2] 87 77 [2] b8 6b }

  condition:
    any of them
}