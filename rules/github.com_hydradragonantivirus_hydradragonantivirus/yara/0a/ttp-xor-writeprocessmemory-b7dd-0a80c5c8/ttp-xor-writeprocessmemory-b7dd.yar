rule TTP_XOR_WriteProcessMemory_b7dd {
  strings:
    $key_b7dd = { e0 af [2] d2 8d [2] d4 b8 [2] fa b8 [2] c5 a4 }

  condition:
    any of them
}