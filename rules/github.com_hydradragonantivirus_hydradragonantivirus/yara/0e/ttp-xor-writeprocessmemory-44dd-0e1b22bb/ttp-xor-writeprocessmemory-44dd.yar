rule TTP_XOR_WriteProcessMemory_44dd {
  strings:
    $key_44dd = { 13 af [2] 21 8d [2] 27 b8 [2] 09 b8 [2] 36 a4 }

  condition:
    any of them
}