rule TTP_XOR_WriteProcessMemory_9a7e {
  strings:
    $key_9a7e = { cd 0c [2] ff 2e [2] f9 1b [2] d7 1b [2] e8 07 }

  condition:
    any of them
}