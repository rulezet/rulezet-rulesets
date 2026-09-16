rule TTP_XOR_WriteProcessMemory_9a55 {
  strings:
    $key_9a55 = { cd 27 [2] ff 05 [2] f9 30 [2] d7 30 [2] e8 2c }

  condition:
    any of them
}