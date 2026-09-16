rule TTP_XOR_WriteProcessMemory_1a08 {
  strings:
    $key_1a08 = { 4d 7a [2] 7f 58 [2] 79 6d [2] 57 6d [2] 68 71 }

  condition:
    any of them
}