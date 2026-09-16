rule TTP_XOR_WriteProcessMemory_9a46 {
  strings:
    $key_9a46 = { cd 34 [2] ff 16 [2] f9 23 [2] d7 23 [2] e8 3f }

  condition:
    any of them
}