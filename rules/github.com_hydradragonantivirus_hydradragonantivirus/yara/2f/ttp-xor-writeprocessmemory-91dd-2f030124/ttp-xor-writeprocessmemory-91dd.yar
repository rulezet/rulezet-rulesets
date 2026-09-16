rule TTP_XOR_WriteProcessMemory_91dd {
  strings:
    $key_91dd = { c6 af [2] f4 8d [2] f2 b8 [2] dc b8 [2] e3 a4 }

  condition:
    any of them
}