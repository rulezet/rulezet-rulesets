rule TTP_XOR_WriteProcessMemory_4636 {
  strings:
    $key_4636 = { 11 44 [2] 23 66 [2] 25 53 [2] 0b 53 [2] 34 4f }

  condition:
    any of them
}