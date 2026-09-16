rule TTP_XOR_WriteProcessMemory_9a03 {
  strings:
    $key_9a03 = { cd 71 [2] ff 53 [2] f9 66 [2] d7 66 [2] e8 7a }

  condition:
    any of them
}