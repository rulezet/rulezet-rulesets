rule TTP_XOR_WriteProcessMemory_9aec {
  strings:
    $key_9aec = { cd 9e [2] ff bc [2] f9 89 [2] d7 89 [2] e8 95 }

  condition:
    any of them
}