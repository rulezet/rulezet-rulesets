rule TTP_XOR_WriteProcessMemory_83dd {
  strings:
    $key_83dd = { d4 af [2] e6 8d [2] e0 b8 [2] ce b8 [2] f1 a4 }

  condition:
    any of them
}