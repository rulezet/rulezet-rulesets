rule TTP_XOR_WriteProcessMemory_94cb {
  strings:
    $key_94cb = { c3 b9 [2] f1 9b [2] f7 ae [2] d9 ae [2] e6 b2 }

  condition:
    any of them
}