rule TTP_XOR_WriteProcessMemory_9a6e {
  strings:
    $key_9a6e = { cd 1c [2] ff 3e [2] f9 0b [2] d7 0b [2] e8 17 }

  condition:
    any of them
}