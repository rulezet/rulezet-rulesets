rule TTP_XOR_WriteProcessMemory_4008 {
  strings:
    $key_4008 = { 17 7a [2] 25 58 [2] 23 6d [2] 0d 6d [2] 32 71 }

  condition:
    any of them
}