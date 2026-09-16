rule TTP_XOR_WriteProcessMemory_46cb {
  strings:
    $key_46cb = { 11 b9 [2] 23 9b [2] 25 ae [2] 0b ae [2] 34 b2 }

  condition:
    any of them
}