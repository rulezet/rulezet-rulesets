rule TTP_XOR_WriteProcessMemory_9aeb {
  strings:
    $key_9aeb = { cd 99 [2] ff bb [2] f9 8e [2] d7 8e [2] e8 92 }

  condition:
    any of them
}