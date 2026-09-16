rule TTP_XOR_WriteProcessMemory_9a60 {
  strings:
    $key_9a60 = { cd 12 [2] ff 30 [2] f9 05 [2] d7 05 [2] e8 19 }

  condition:
    any of them
}