rule TTP_XOR_WriteProcessMemory_46dd {
  strings:
    $key_46dd = { 11 af [2] 23 8d [2] 25 b8 [2] 0b b8 [2] 34 a4 }

  condition:
    any of them
}