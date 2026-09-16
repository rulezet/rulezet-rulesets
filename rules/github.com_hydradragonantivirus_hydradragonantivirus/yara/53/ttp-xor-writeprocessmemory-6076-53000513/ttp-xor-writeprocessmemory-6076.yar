rule TTP_XOR_WriteProcessMemory_6076 {
  strings:
    $key_6076 = { 37 04 [2] 05 26 [2] 03 13 [2] 2d 13 [2] 12 0f }

  condition:
    any of them
}