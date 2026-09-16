rule TTP_XOR_WriteProcessMemory_ca53 {
  strings:
    $key_ca53 = { 9d 21 [2] af 03 [2] a9 36 [2] 87 36 [2] b8 2a }

  condition:
    any of them
}