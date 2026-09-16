rule TTP_XOR_WriteProcessMemory_20dd {
  strings:
    $key_20dd = { 77 af [2] 45 8d [2] 43 b8 [2] 6d b8 [2] 52 a4 }

  condition:
    any of them
}