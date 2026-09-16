rule TTP_XOR_WriteProcessMemory_9a66 {
  strings:
    $key_9a66 = { cd 14 [2] ff 36 [2] f9 03 [2] d7 03 [2] e8 1f }

  condition:
    any of them
}