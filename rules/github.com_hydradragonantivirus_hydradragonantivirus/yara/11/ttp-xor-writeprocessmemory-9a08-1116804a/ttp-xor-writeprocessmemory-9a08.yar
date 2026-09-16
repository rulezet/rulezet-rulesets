rule TTP_XOR_WriteProcessMemory_9a08 {
  strings:
    $key_9a08 = { cd 7a [2] ff 58 [2] f9 6d [2] d7 6d [2] e8 71 }

  condition:
    any of them
}