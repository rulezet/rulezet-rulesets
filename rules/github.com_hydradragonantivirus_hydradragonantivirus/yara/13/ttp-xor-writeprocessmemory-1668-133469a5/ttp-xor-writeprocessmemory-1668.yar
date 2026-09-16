rule TTP_XOR_WriteProcessMemory_1668 {
  strings:
    $key_1668 = { 41 1a [2] 73 38 [2] 75 0d [2] 5b 0d [2] 64 11 }

  condition:
    any of them
}