rule TTP_XOR_WriteProcessMemory_9a2c {
  strings:
    $key_9a2c = { cd 5e [2] ff 7c [2] f9 49 [2] d7 49 [2] e8 55 }

  condition:
    any of them
}