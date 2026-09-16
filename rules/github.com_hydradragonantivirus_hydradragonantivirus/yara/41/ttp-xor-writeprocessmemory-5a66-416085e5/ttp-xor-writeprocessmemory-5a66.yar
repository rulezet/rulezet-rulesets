rule TTP_XOR_WriteProcessMemory_5a66 {
  strings:
    $key_5a66 = { 0d 14 [2] 3f 36 [2] 39 03 [2] 17 03 [2] 28 1f }

  condition:
    any of them
}