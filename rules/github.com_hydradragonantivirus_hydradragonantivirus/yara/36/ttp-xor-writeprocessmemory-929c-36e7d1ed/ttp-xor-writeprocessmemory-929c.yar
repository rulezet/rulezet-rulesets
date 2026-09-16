rule TTP_XOR_WriteProcessMemory_929c {
  strings:
    $key_929c = { c5 ee [2] f7 cc [2] f1 f9 [2] df f9 [2] e0 e5 }

  condition:
    any of them
}