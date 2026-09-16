rule TTP_XOR_WriteProcessMemory_76cb {
  strings:
    $key_76cb = { 21 b9 [2] 13 9b [2] 15 ae [2] 3b ae [2] 04 b2 }

  condition:
    any of them
}