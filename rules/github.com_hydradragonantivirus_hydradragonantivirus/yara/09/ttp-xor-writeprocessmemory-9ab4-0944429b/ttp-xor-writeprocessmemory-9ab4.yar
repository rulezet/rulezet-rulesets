rule TTP_XOR_WriteProcessMemory_9ab4 {
  strings:
    $key_9ab4 = { cd c6 [2] ff e4 [2] f9 d1 [2] d7 d1 [2] e8 cd }

  condition:
    any of them
}