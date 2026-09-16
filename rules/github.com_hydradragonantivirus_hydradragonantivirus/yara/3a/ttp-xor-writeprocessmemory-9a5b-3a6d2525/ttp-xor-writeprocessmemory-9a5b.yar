rule TTP_XOR_WriteProcessMemory_9a5b {
  strings:
    $key_9a5b = { cd 29 [2] ff 0b [2] f9 3e [2] d7 3e [2] e8 22 }

  condition:
    any of them
}