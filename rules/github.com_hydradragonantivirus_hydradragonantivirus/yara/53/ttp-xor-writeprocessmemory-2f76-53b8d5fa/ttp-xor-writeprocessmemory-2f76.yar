rule TTP_XOR_WriteProcessMemory_2f76 {
  strings:
    $key_2f76 = { 78 04 [2] 4a 26 [2] 4c 13 [2] 62 13 [2] 5d 0f }

  condition:
    any of them
}