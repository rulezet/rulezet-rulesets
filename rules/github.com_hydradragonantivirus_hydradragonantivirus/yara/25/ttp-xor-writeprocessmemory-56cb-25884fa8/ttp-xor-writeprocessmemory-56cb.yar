rule TTP_XOR_WriteProcessMemory_56cb {
  strings:
    $key_56cb = { 01 b9 [2] 33 9b [2] 35 ae [2] 1b ae [2] 24 b2 }

  condition:
    any of them
}