rule TTP_XOR_WriteProcessMemory_93cb {
  strings:
    $key_93cb = { c4 b9 [2] f6 9b [2] f0 ae [2] de ae [2] e1 b2 }

  condition:
    any of them
}