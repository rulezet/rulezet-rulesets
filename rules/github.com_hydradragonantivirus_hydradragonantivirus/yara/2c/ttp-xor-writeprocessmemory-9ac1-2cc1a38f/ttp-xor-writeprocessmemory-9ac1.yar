rule TTP_XOR_WriteProcessMemory_9ac1 {
  strings:
    $key_9ac1 = { cd b3 [2] ff 91 [2] f9 a4 [2] d7 a4 [2] e8 b8 }

  condition:
    any of them
}