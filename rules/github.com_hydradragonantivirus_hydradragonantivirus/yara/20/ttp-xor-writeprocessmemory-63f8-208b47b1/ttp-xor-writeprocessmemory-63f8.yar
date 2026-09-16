rule TTP_XOR_WriteProcessMemory_63f8 {
  strings:
    $key_63f8 = { 34 8a [2] 06 a8 [2] 00 9d [2] 2e 9d [2] 11 81 }

  condition:
    any of them
}