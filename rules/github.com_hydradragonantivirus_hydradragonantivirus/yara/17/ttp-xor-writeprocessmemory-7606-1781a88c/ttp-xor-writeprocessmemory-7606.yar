rule TTP_XOR_WriteProcessMemory_7606 {
  strings:
    $key_7606 = { 21 74 [2] 13 56 [2] 15 63 [2] 3b 63 [2] 04 7f }

  condition:
    any of them
}