rule TTP_XOR_WriteProcessMemory_9a51 {
  strings:
    $key_9a51 = { cd 23 [2] ff 01 [2] f9 34 [2] d7 34 [2] e8 28 }

  condition:
    any of them
}