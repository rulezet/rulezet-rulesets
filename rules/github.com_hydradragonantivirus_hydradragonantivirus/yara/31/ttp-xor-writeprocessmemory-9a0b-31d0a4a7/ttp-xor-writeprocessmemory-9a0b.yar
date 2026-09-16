rule TTP_XOR_WriteProcessMemory_9a0b {
  strings:
    $key_9a0b = { cd 79 [2] ff 5b [2] f9 6e [2] d7 6e [2] e8 72 }

  condition:
    any of them
}