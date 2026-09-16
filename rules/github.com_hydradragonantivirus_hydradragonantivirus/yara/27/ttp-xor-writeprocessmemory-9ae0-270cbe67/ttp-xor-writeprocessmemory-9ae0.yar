rule TTP_XOR_WriteProcessMemory_9ae0 {
  strings:
    $key_9ae0 = { cd 92 [2] ff b0 [2] f9 85 [2] d7 85 [2] e8 99 }

  condition:
    any of them
}