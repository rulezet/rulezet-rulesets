rule TTP_XOR_WriteProcessMemory_9afc {
  strings:
    $key_9afc = { cd 8e [2] ff ac [2] f9 99 [2] d7 99 [2] e8 85 }

  condition:
    any of them
}