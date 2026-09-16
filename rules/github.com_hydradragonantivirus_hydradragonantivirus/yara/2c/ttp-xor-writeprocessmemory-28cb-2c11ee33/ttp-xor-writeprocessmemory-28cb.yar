rule TTP_XOR_WriteProcessMemory_28cb {
  strings:
    $key_28cb = { 7f b9 [2] 4d 9b [2] 4b ae [2] 65 ae [2] 5a b2 }

  condition:
    any of them
}