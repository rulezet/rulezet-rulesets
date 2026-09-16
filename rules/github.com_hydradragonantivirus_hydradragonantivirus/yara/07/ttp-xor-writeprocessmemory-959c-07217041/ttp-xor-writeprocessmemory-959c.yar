rule TTP_XOR_WriteProcessMemory_959c {
  strings:
    $key_959c = { c2 ee [2] f0 cc [2] f6 f9 [2] d8 f9 [2] e7 e5 }

  condition:
    any of them
}