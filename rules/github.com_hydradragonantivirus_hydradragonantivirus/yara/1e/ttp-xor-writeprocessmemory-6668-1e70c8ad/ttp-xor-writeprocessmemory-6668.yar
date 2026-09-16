rule TTP_XOR_WriteProcessMemory_6668 {
  strings:
    $key_6668 = { 31 1a [2] 03 38 [2] 05 0d [2] 2b 0d [2] 14 11 }

  condition:
    any of them
}