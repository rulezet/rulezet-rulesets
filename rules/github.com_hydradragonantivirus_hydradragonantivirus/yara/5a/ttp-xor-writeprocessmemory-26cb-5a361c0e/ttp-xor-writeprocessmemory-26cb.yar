rule TTP_XOR_WriteProcessMemory_26cb {
  strings:
    $key_26cb = { 71 b9 [2] 43 9b [2] 45 ae [2] 6b ae [2] 54 b2 }

  condition:
    any of them
}