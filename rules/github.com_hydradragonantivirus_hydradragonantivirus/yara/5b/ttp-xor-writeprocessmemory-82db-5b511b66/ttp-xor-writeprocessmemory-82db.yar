rule TTP_XOR_WriteProcessMemory_82db {
  strings:
    $key_82db = { d5 a9 [2] e7 8b [2] e1 be [2] cf be [2] f0 a2 }

  condition:
    any of them
}