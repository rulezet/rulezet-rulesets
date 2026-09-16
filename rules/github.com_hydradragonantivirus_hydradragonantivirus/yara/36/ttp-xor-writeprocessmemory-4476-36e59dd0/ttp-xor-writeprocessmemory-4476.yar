rule TTP_XOR_WriteProcessMemory_4476 {
  strings:
    $key_4476 = { 13 04 [2] 21 26 [2] 27 13 [2] 09 13 [2] 36 0f }

  condition:
    any of them
}