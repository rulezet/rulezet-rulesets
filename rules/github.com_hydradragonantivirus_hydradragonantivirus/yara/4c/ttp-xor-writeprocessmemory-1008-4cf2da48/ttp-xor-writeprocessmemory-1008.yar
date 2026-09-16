rule TTP_XOR_WriteProcessMemory_1008 {
  strings:
    $key_1008 = { 47 7a [2] 75 58 [2] 73 6d [2] 5d 6d [2] 62 71 }

  condition:
    any of them
}