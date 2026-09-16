rule TTP_XOR_WriteProcessMemory_9a49 {
  strings:
    $key_9a49 = { cd 3b [2] ff 19 [2] f9 2c [2] d7 2c [2] e8 30 }

  condition:
    any of them
}