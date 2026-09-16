rule TTP_XOR_WriteProcessMemory_97ce {
  strings:
    $key_97ce = { c0 bc [2] f2 9e [2] f4 ab [2] da ab [2] e5 b7 }

  condition:
    any of them
}