rule TTP_XOR_WriteProcessMemory_a7dd {
  strings:
    $key_a7dd = { f0 af [2] c2 8d [2] c4 b8 [2] ea b8 [2] d5 a4 }

  condition:
    any of them
}