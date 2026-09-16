rule TTP_XOR_WriteProcessMemory_3068 {
  strings:
    $key_3068 = { 67 1a [2] 55 38 [2] 53 0d [2] 7d 0d [2] 42 11 }

  condition:
    any of them
}