rule TTP_XOR_WriteProcessMemory_82bc {
  strings:
    $key_82bc = { d5 ce [2] e7 ec [2] e1 d9 [2] cf d9 [2] f0 c5 }

  condition:
    any of them
}