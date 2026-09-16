rule TTP_XOR_WriteProcessMemory_1656 {
  strings:
    $key_1656 = { 41 24 [2] 73 06 [2] 75 33 [2] 5b 33 [2] 64 2f }

  condition:
    any of them
}