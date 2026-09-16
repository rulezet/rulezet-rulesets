rule TTP_XOR_WriteProcessMemory_848b {
  strings:
    $key_848b = { d3 f9 [2] e1 db [2] e7 ee [2] c9 ee [2] f6 f2 }

  condition:
    any of them
}