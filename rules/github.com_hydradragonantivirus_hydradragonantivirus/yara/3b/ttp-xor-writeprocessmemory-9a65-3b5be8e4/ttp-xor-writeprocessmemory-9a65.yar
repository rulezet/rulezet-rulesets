rule TTP_XOR_WriteProcessMemory_9a65 {
  strings:
    $key_9a65 = { cd 17 [2] ff 35 [2] f9 00 [2] d7 00 [2] e8 1c }

  condition:
    any of them
}