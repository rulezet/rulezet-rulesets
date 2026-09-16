rule TTP_XOR_WriteProcessMemory_808c {
  strings:
    $key_808c = { d7 fe [2] e5 dc [2] e3 e9 [2] cd e9 [2] f2 f5 }

  condition:
    any of them
}