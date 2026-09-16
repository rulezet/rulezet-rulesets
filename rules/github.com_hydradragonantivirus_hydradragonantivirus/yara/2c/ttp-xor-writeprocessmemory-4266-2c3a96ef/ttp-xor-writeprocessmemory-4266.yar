rule TTP_XOR_WriteProcessMemory_4266 {
  strings:
    $key_4266 = { 15 14 [2] 27 36 [2] 21 03 [2] 0f 03 [2] 30 1f }

  condition:
    any of them
}