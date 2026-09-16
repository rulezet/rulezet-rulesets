rule TTP_XOR_WriteProcessMemory_9ab5 {
  strings:
    $key_9ab5 = { cd c7 [2] ff e5 [2] f9 d0 [2] d7 d0 [2] e8 cc }

  condition:
    any of them
}