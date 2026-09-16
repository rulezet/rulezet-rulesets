rule TTP_XOR_WriteProcessMemory_9ae6 {
  strings:
    $key_9ae6 = { cd 94 [2] ff b6 [2] f9 83 [2] d7 83 [2] e8 9f }

  condition:
    any of them
}