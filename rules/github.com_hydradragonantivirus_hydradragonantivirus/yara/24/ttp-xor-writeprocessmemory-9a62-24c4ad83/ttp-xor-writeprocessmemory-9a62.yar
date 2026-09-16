rule TTP_XOR_WriteProcessMemory_9a62 {
  strings:
    $key_9a62 = { cd 10 [2] ff 32 [2] f9 07 [2] d7 07 [2] e8 1b }

  condition:
    any of them
}