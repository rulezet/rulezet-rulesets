rule TTP_XOR_WriteProcessMemory_4536 {
  strings:
    $key_4536 = { 12 44 [2] 20 66 [2] 26 53 [2] 08 53 [2] 37 4f }

  condition:
    any of them
}