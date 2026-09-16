rule TTP_XOR_WriteProcessMemory_9a42 {
  strings:
    $key_9a42 = { cd 30 [2] ff 12 [2] f9 27 [2] d7 27 [2] e8 3b }

  condition:
    any of them
}