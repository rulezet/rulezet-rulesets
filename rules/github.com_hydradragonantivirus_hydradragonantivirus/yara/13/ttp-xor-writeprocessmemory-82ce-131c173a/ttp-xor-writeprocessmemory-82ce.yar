rule TTP_XOR_WriteProcessMemory_82ce {
  strings:
    $key_82ce = { d5 bc [2] e7 9e [2] e1 ab [2] cf ab [2] f0 b7 }

  condition:
    any of them
}