rule TTP_XOR_WriteProcessMemory_9aad {
  strings:
    $key_9aad = { cd df [2] ff fd [2] f9 c8 [2] d7 c8 [2] e8 d4 }

  condition:
    any of them
}