rule TTP_XOR_WriteProcessMemory_7708 {
  strings:
    $key_7708 = { 20 7a [2] 12 58 [2] 14 6d [2] 3a 6d [2] 05 71 }

  condition:
    any of them
}