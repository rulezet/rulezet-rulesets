rule TTP_XOR_WriteProcessMemory_9aac {
  strings:
    $key_9aac = { cd de [2] ff fc [2] f9 c9 [2] d7 c9 [2] e8 d5 }

  condition:
    any of them
}