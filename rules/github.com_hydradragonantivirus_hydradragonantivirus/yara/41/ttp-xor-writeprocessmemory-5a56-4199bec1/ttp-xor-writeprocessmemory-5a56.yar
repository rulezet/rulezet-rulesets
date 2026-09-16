rule TTP_XOR_WriteProcessMemory_5a56 {
  strings:
    $key_5a56 = { 0d 24 [2] 3f 06 [2] 39 33 [2] 17 33 [2] 28 2f }

  condition:
    any of them
}