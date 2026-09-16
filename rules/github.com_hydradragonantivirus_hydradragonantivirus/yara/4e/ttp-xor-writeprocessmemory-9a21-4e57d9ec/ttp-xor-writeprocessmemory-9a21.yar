rule TTP_XOR_WriteProcessMemory_9a21 {
  strings:
    $key_9a21 = { cd 53 [2] ff 71 [2] f9 44 [2] d7 44 [2] e8 58 }

  condition:
    any of them
}