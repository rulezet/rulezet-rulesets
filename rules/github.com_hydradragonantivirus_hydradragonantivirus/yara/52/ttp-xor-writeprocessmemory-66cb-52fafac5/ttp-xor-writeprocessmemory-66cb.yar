rule TTP_XOR_WriteProcessMemory_66cb {
  strings:
    $key_66cb = { 31 b9 [2] 03 9b [2] 05 ae [2] 2b ae [2] 14 b2 }

  condition:
    any of them
}