rule TTP_XOR_WriteProcessMemory_1a18 {
  strings:
    $key_1a18 = { 4d 6a [2] 7f 48 [2] 79 7d [2] 57 7d [2] 68 61 }

  condition:
    any of them
}