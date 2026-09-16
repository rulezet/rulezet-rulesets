rule TTP_XOR_WriteProcessMemory_9a6c {
  strings:
    $key_9a6c = { cd 1e [2] ff 3c [2] f9 09 [2] d7 09 [2] e8 15 }

  condition:
    any of them
}