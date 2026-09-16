rule TTP_XOR_WriteProcessMemory_b49c {
  strings:
    $key_b49c = { e3 ee [2] d1 cc [2] d7 f9 [2] f9 f9 [2] c6 e5 }

  condition:
    any of them
}