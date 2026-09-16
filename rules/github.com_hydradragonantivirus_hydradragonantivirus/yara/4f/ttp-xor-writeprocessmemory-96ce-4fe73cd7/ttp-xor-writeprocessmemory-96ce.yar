rule TTP_XOR_WriteProcessMemory_96ce {
  strings:
    $key_96ce = { c1 bc [2] f3 9e [2] f5 ab [2] db ab [2] e4 b7 }

  condition:
    any of them
}