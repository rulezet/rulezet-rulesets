rule TTP_XOR_WriteProcessMemory_4368 {
  strings:
    $key_4368 = { 14 1a [2] 26 38 [2] 20 0d [2] 0e 0d [2] 31 11 }

  condition:
    any of them
}