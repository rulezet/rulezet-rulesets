rule TTP_XOR_WriteProcessMemory_839c {
  strings:
    $key_839c = { d4 ee [2] e6 cc [2] e0 f9 [2] ce f9 [2] f1 e5 }

  condition:
    any of them
}