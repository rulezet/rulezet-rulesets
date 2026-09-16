rule TTP_XOR_WriteProcessMemory_5968 {
  strings:
    $key_5968 = { 0e 1a [2] 3c 38 [2] 3a 0d [2] 14 0d [2] 2b 11 }

  condition:
    any of them
}