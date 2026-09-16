rule TTP_XOR_WriteProcessMemory_9a07 {
  strings:
    $key_9a07 = { cd 75 [2] ff 57 [2] f9 62 [2] d7 62 [2] e8 7e }

  condition:
    any of them
}