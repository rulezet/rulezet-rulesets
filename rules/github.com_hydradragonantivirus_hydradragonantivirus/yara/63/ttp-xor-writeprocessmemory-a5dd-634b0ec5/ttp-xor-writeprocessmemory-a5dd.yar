rule TTP_XOR_WriteProcessMemory_a5dd {
  strings:
    $key_a5dd = { f2 af [2] c0 8d [2] c6 b8 [2] e8 b8 [2] d7 a4 }

  condition:
    any of them
}