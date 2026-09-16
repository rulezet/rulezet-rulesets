rule TTP_XOR_WriteProcessMemory_9ab7 {
  strings:
    $key_9ab7 = { cd c5 [2] ff e7 [2] f9 d2 [2] d7 d2 [2] e8 ce }

  condition:
    any of them
}