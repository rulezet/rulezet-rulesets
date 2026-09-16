rule TTP_XOR_WriteProcessMemory_9a82 {
  strings:
    $key_9a82 = { cd f0 [2] ff d2 [2] f9 e7 [2] d7 e7 [2] e8 fb }

  condition:
    any of them
}