rule TTP_XOR_WriteProcessMemory_9a2e {
  strings:
    $key_9a2e = { cd 5c [2] ff 7e [2] f9 4b [2] d7 4b [2] e8 57 }

  condition:
    any of them
}