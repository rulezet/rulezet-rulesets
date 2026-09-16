rule TTP_XOR_WriteProcessMemory_9a71 {
  strings:
    $key_9a71 = { cd 03 [2] ff 21 [2] f9 14 [2] d7 14 [2] e8 08 }

  condition:
    any of them
}