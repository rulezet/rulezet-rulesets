rule TTP_XOR_WriteProcessMemory_93dd {
  strings:
    $key_93dd = { c4 af [2] f6 8d [2] f0 b8 [2] de b8 [2] e1 a4 }

  condition:
    any of them
}