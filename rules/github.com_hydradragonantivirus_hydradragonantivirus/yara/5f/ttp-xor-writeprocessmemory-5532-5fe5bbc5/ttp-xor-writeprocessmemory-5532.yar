rule TTP_XOR_WriteProcessMemory_5532 {
  strings:
    $key_5532 = { 02 40 [2] 30 62 [2] 36 57 [2] 18 57 [2] 27 4b }

  condition:
    any of them
}