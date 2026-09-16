rule TTP_XOR_WriteProcessMemory_958b {
  strings:
    $key_958b = { c2 f9 [2] f0 db [2] f6 ee [2] d8 ee [2] e7 f2 }

  condition:
    any of them
}