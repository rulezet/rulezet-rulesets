rule TTP_XOR_WriteProcessMemory_a6dd {
  strings:
    $key_a6dd = { f1 af [2] c3 8d [2] c5 b8 [2] eb b8 [2] d4 a4 }

  condition:
    any of them
}