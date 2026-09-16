rule TTP_XOR_WriteProcessMemory_1b76 {
  strings:
    $key_1b76 = { 4c 04 [2] 7e 26 [2] 78 13 [2] 56 13 [2] 69 0f }

  condition:
    any of them
}