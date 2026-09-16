rule TTP_XOR_WriteProcessMemory_5ae2 {
  strings:
    $key_5ae2 = { 0d 90 [2] 3f b2 [2] 39 87 [2] 17 87 [2] 28 9b }

  condition:
    any of them
}