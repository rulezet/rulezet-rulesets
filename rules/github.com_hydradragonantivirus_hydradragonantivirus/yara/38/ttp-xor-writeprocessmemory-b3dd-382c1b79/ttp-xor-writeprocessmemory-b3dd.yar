rule TTP_XOR_WriteProcessMemory_b3dd {
  strings:
    $key_b3dd = { e4 af [2] d6 8d [2] d0 b8 [2] fe b8 [2] c1 a4 }

  condition:
    any of them
}