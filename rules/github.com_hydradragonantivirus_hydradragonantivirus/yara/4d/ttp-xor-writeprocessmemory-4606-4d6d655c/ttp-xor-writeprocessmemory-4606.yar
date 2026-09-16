rule TTP_XOR_WriteProcessMemory_4606 {
  strings:
    $key_4606 = { 11 74 [2] 23 56 [2] 25 63 [2] 0b 63 [2] 34 7f }

  condition:
    any of them
}