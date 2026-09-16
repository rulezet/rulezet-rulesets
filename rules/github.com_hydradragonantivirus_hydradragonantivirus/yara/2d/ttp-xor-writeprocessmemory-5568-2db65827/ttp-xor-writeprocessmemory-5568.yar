rule TTP_XOR_WriteProcessMemory_5568 {
  strings:
    $key_5568 = { 02 1a [2] 30 38 [2] 36 0d [2] 18 0d [2] 27 11 }

  condition:
    any of them
}