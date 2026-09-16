rule TTP_XOR_WriteProcessMemory_5108 {
  strings:
    $key_5108 = { 06 7a [2] 34 58 [2] 32 6d [2] 1c 6d [2] 23 71 }

  condition:
    any of them
}