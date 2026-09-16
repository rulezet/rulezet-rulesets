rule TTP_XOR_WriteProcessMemory_86cb {
  strings:
    $key_86cb = { d1 b9 [2] e3 9b [2] e5 ae [2] cb ae [2] f4 b2 }

  condition:
    any of them
}