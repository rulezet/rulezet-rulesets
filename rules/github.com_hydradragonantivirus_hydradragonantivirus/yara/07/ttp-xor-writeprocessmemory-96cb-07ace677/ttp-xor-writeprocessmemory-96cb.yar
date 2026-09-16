rule TTP_XOR_WriteProcessMemory_96cb {
  strings:
    $key_96cb = { c1 b9 [2] f3 9b [2] f5 ae [2] db ae [2] e4 b2 }

  condition:
    any of them
}