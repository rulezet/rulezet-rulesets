rule TTP_XOR_WriteProcessMemory_64dd {
  strings:
    $key_64dd = { 33 af [2] 01 8d [2] 07 b8 [2] 29 b8 [2] 16 a4 }

  condition:
    any of them
}