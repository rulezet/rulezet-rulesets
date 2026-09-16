rule TTP_XOR_WriteProcessMemory_1768 {
  strings:
    $key_1768 = { 40 1a [2] 72 38 [2] 74 0d [2] 5a 0d [2] 65 11 }

  condition:
    any of them
}