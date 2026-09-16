rule TTP_XOR_WriteProcessMemory_879c {
  strings:
    $key_879c = { d0 ee [2] e2 cc [2] e4 f9 [2] ca f9 [2] f5 e5 }

  condition:
    any of them
}