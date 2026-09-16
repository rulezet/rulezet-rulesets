rule TTP_XOR_WriteProcessMemory_7846 {
  strings:
    $key_7846 = { 2f 34 [2] 1d 16 [2] 1b 23 [2] 35 23 [2] 0a 3f }

  condition:
    any of them
}