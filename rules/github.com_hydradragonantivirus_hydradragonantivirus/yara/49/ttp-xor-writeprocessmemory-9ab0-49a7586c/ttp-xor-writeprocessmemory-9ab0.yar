rule TTP_XOR_WriteProcessMemory_9ab0 {
  strings:
    $key_9ab0 = { cd c2 [2] ff e0 [2] f9 d5 [2] d7 d5 [2] e8 c9 }

  condition:
    any of them
}