rule TTP_XOR_WriteProcessMemory_4308 {
  strings:
    $key_4308 = { 14 7a [2] 26 58 [2] 20 6d [2] 0e 6d [2] 31 71 }

  condition:
    any of them
}