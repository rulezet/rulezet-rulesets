rule TTP_XOR_WriteProcessMemory_9a1b {
  strings:
    $key_9a1b = { cd 69 [2] ff 4b [2] f9 7e [2] d7 7e [2] e8 62 }

  condition:
    any of them
}