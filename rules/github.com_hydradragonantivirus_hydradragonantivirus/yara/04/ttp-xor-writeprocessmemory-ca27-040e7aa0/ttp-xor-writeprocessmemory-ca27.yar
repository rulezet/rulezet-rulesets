rule TTP_XOR_WriteProcessMemory_ca27 {
  strings:
    $key_ca27 = { 9d 55 [2] af 77 [2] a9 42 [2] 87 42 [2] b8 5e }

  condition:
    any of them
}