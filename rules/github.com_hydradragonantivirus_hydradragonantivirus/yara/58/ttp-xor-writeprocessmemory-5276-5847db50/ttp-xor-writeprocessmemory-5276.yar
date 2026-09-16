rule TTP_XOR_WriteProcessMemory_5276 {
  strings:
    $key_5276 = { 05 04 [2] 37 26 [2] 31 13 [2] 1f 13 [2] 20 0f }

  condition:
    any of them
}