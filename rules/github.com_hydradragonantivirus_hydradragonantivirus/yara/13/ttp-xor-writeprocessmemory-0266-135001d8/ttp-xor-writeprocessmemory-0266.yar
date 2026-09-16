rule TTP_XOR_WriteProcessMemory_0266 {
  strings:
    $key_0266 = { 55 14 [2] 67 36 [2] 61 03 [2] 4f 03 [2] 70 1f }

  condition:
    any of them
}