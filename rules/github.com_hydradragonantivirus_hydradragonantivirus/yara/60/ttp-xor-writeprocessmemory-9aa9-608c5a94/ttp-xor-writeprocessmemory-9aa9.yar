rule TTP_XOR_WriteProcessMemory_9aa9 {
  strings:
    $key_9aa9 = { cd db [2] ff f9 [2] f9 cc [2] d7 cc [2] e8 d0 }

  condition:
    any of them
}