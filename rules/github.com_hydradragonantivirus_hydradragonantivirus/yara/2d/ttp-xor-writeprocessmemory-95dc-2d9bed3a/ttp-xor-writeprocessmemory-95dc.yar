rule TTP_XOR_WriteProcessMemory_95dc {
  strings:
    $key_95dc = { c2 ae [2] f0 8c [2] f6 b9 [2] d8 b9 [2] e7 a5 }

  condition:
    any of them
}