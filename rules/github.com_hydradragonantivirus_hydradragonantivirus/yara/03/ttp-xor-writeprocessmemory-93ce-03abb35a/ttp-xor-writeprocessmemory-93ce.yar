rule TTP_XOR_WriteProcessMemory_93ce {
  strings:
    $key_93ce = { c4 bc [2] f6 9e [2] f0 ab [2] de ab [2] e1 b7 }

  condition:
    any of them
}