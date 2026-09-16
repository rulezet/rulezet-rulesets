rule TTP_XOR_WriteProcessMemory_82cb {
  strings:
    $key_82cb = { d5 b9 [2] e7 9b [2] e1 ae [2] cf ae [2] f0 b2 }

  condition:
    any of them
}