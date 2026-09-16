rule TTP_XOR_WriteProcessMemory_e4cb {
  strings:
    $key_e4cb = { b3 b9 [2] 81 9b [2] 87 ae [2] a9 ae [2] 96 b2 }

  condition:
    any of them
}