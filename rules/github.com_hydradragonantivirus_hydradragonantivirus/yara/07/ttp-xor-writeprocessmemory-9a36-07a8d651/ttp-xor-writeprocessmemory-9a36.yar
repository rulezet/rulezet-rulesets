rule TTP_XOR_WriteProcessMemory_9a36 {
  strings:
    $key_9a36 = { cd 44 [2] ff 66 [2] f9 53 [2] d7 53 [2] e8 4f }

  condition:
    any of them
}