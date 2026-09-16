rule TTP_XOR_WriteProcessMemory_9ab3 {
  strings:
    $key_9ab3 = { cd c1 [2] ff e3 [2] f9 d6 [2] d7 d6 [2] e8 ca }

  condition:
    any of them
}