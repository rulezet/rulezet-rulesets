rule TTP_XOR_WriteProcessMemory_9a70 {
  strings:
    $key_9a70 = { cd 02 [2] ff 20 [2] f9 15 [2] d7 15 [2] e8 09 }

  condition:
    any of them
}