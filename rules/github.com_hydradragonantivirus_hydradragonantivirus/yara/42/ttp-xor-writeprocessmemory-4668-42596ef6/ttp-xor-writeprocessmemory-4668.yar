rule TTP_XOR_WriteProcessMemory_4668 {
  strings:
    $key_4668 = { 11 1a [2] 23 38 [2] 25 0d [2] 0b 0d [2] 34 11 }

  condition:
    any of them
}