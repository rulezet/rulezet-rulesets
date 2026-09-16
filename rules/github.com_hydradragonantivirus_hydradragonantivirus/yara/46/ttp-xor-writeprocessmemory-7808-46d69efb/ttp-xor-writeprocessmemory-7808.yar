rule TTP_XOR_WriteProcessMemory_7808 {
  strings:
    $key_7808 = { 2f 7a [2] 1d 58 [2] 1b 6d [2] 35 6d [2] 0a 71 }

  condition:
    any of them
}