rule TTP_XOR_WriteProcessMemory_a6cb {
  strings:
    $key_a6cb = { f1 b9 [2] c3 9b [2] c5 ae [2] eb ae [2] d4 b2 }

  condition:
    any of them
}