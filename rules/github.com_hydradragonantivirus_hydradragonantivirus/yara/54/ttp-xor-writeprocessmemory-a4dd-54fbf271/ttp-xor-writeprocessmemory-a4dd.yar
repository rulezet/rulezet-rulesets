rule TTP_XOR_WriteProcessMemory_a4dd {
  strings:
    $key_a4dd = { f3 af [2] c1 8d [2] c7 b8 [2] e9 b8 [2] d6 a4 }

  condition:
    any of them
}