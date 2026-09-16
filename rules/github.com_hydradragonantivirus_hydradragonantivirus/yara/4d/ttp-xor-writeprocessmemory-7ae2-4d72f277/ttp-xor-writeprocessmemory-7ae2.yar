rule TTP_XOR_WriteProcessMemory_7ae2 {
  strings:
    $key_7ae2 = { 2d 90 [2] 1f b2 [2] 19 87 [2] 37 87 [2] 08 9b }

  condition:
    any of them
}