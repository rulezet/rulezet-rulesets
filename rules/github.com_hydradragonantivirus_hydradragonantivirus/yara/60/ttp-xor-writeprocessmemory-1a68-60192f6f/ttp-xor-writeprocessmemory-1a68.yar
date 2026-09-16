rule TTP_XOR_WriteProcessMemory_1a68 {
  strings:
    $key_1a68 = { 4d 1a [2] 7f 38 [2] 79 0d [2] 57 0d [2] 68 11 }

  condition:
    any of them
}