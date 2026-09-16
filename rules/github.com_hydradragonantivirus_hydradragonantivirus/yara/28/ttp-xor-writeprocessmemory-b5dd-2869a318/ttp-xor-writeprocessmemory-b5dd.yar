rule TTP_XOR_WriteProcessMemory_b5dd {
  strings:
    $key_b5dd = { e2 af [2] d0 8d [2] d6 b8 [2] f8 b8 [2] c7 a4 }

  condition:
    any of them
}