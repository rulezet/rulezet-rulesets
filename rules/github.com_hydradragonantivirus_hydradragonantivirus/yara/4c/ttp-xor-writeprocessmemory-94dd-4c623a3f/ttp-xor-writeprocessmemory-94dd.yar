rule TTP_XOR_WriteProcessMemory_94dd {
  strings:
    $key_94dd = { c3 af [2] f1 8d [2] f7 b8 [2] d9 b8 [2] e6 a4 }

  condition:
    any of them
}