rule TTP_XOR_WriteProcessMemory_23cb {
  strings:
    $key_23cb = { 74 b9 [2] 46 9b [2] 40 ae [2] 6e ae [2] 51 b2 }

  condition:
    any of them
}