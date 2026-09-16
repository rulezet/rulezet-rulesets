rule TTP_XOR_WriteProcessMemory_1608 {
  strings:
    $key_1608 = { 41 7a [2] 73 58 [2] 75 6d [2] 5b 6d [2] 64 71 }

  condition:
    any of them
}