rule TTP_XOR_WriteProcessMemory_5708 {
  strings:
    $key_5708 = { 00 7a [2] 32 58 [2] 34 6d [2] 1a 6d [2] 25 71 }

  condition:
    any of them
}