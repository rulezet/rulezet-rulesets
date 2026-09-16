rule TTP_XOR_WriteProcessMemory_9a5e {
  strings:
    $key_9a5e = { cd 2c [2] ff 0e [2] f9 3b [2] d7 3b [2] e8 27 }

  condition:
    any of them
}