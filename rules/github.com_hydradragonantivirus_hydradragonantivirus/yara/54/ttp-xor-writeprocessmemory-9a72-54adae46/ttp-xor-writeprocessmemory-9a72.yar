rule TTP_XOR_WriteProcessMemory_9a72 {
  strings:
    $key_9a72 = { cd 00 [2] ff 22 [2] f9 17 [2] d7 17 [2] e8 0b }

  condition:
    any of them
}