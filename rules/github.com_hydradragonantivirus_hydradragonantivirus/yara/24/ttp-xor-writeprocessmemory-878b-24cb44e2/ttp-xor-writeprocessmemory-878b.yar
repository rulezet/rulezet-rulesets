rule TTP_XOR_WriteProcessMemory_878b {
  strings:
    $key_878b = { d0 f9 [2] e2 db [2] e4 ee [2] ca ee [2] f5 f2 }

  condition:
    any of them
}