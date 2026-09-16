rule TTP_XOR_WriteProcessMemory_56dd {
  strings:
    $key_56dd = { 01 af [2] 33 8d [2] 35 b8 [2] 1b b8 [2] 24 a4 }

  condition:
    any of them
}