rule TTP_XOR_WriteProcessMemory_50dd {
  strings:
    $key_50dd = { 07 af [2] 35 8d [2] 33 b8 [2] 1d b8 [2] 22 a4 }

  condition:
    any of them
}