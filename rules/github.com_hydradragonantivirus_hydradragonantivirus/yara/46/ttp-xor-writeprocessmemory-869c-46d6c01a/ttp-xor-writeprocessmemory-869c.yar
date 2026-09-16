rule TTP_XOR_WriteProcessMemory_869c {
  strings:
    $key_869c = { d1 ee [2] e3 cc [2] e5 f9 [2] cb f9 [2] f4 e5 }

  condition:
    any of them
}