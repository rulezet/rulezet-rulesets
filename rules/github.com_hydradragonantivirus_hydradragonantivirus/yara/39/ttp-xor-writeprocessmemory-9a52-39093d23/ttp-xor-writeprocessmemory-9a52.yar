rule TTP_XOR_WriteProcessMemory_9a52 {
  strings:
    $key_9a52 = { cd 20 [2] ff 02 [2] f9 37 [2] d7 37 [2] e8 2b }

  condition:
    any of them
}