rule TTP_XOR_WriteProcessMemory_48dc {
  strings:
    $key_48dc = { 1f ae [2] 2d 8c [2] 2b b9 [2] 05 b9 [2] 3a a5 }

  condition:
    any of them
}