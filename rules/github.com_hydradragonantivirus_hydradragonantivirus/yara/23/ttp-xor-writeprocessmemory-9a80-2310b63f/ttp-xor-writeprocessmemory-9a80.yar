rule TTP_XOR_WriteProcessMemory_9a80 {
  strings:
    $key_9a80 = { cd f2 [2] ff d0 [2] f9 e5 [2] d7 e5 [2] e8 f9 }

  condition:
    any of them
}