rule TTP_XOR_WriteProcessMemory_9a06 {
  strings:
    $key_9a06 = { cd 74 [2] ff 56 [2] f9 63 [2] d7 63 [2] e8 7f }

  condition:
    any of them
}