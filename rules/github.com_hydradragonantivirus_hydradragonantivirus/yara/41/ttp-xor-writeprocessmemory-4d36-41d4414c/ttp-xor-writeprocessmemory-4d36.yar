rule TTP_XOR_WriteProcessMemory_4d36 {
  strings:
    $key_4d36 = { 1a 44 [2] 28 66 [2] 2e 53 [2] 00 53 [2] 3f 4f }

  condition:
    any of them
}