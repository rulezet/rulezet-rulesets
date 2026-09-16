rule TTP_XOR_WriteProcessMemory_1b56 {
  strings:
    $key_1b56 = { 4c 24 [2] 7e 06 [2] 78 33 [2] 56 33 [2] 69 2f }

  condition:
    any of them
}