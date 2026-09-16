rule TTP_XOR_WriteProcessMemory_9a4c {
  strings:
    $key_9a4c = { cd 3e [2] ff 1c [2] f9 29 [2] d7 29 [2] e8 35 }

  condition:
    any of them
}