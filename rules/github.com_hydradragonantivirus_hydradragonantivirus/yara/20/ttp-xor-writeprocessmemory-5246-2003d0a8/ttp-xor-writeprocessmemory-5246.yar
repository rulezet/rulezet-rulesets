rule TTP_XOR_WriteProcessMemory_5246 {
  strings:
    $key_5246 = { 05 34 [2] 37 16 [2] 31 23 [2] 1f 23 [2] 20 3f }

  condition:
    any of them
}