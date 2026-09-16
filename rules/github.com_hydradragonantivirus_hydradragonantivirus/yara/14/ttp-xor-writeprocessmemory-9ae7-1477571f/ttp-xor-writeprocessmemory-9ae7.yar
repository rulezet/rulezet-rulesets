rule TTP_XOR_WriteProcessMemory_9ae7 {
  strings:
    $key_9ae7 = { cd 95 [2] ff b7 [2] f9 82 [2] d7 82 [2] e8 9e }

  condition:
    any of them
}