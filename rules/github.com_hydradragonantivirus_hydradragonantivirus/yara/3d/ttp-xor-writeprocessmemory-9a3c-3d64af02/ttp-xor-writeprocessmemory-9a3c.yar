rule TTP_XOR_WriteProcessMemory_9a3c {
  strings:
    $key_9a3c = { cd 4e [2] ff 6c [2] f9 59 [2] d7 59 [2] e8 45 }

  condition:
    any of them
}