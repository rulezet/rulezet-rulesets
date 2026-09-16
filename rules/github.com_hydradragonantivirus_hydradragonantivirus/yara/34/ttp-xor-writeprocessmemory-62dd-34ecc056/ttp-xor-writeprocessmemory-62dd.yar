rule TTP_XOR_WriteProcessMemory_62dd {
  strings:
    $key_62dd = { 35 af [2] 07 8d [2] 01 b8 [2] 2f b8 [2] 10 a4 }

  condition:
    any of them
}