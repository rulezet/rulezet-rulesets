rule TTP_XOR_WriteProcessMemory_4068 {
  strings:
    $key_4068 = { 17 1a [2] 25 38 [2] 23 0d [2] 0d 0d [2] 32 11 }

  condition:
    any of them
}