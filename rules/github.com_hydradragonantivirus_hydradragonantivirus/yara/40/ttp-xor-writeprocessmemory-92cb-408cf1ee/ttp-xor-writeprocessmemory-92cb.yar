rule TTP_XOR_WriteProcessMemory_92cb {
  strings:
    $key_92cb = { c5 b9 [2] f7 9b [2] f1 ae [2] df ae [2] e0 b2 }

  condition:
    any of them
}