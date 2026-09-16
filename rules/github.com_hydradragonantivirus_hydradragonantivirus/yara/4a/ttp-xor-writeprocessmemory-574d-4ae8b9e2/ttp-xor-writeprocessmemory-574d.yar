rule TTP_XOR_WriteProcessMemory_574d {
  strings:
    $key_574d = { 00 3f [2] 32 1d [2] 34 28 [2] 1a 28 [2] 25 34 }

  condition:
    any of them
}