rule TTP_XOR_WriteProcessMemory_a3dd {
  strings:
    $key_a3dd = { f4 af [2] c6 8d [2] c0 b8 [2] ee b8 [2] d1 a4 }

  condition:
    any of them
}