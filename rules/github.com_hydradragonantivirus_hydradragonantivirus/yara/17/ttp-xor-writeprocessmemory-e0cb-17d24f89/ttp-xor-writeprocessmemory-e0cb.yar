rule TTP_XOR_WriteProcessMemory_e0cb {
  strings:
    $key_e0cb = { b7 b9 [2] 85 9b [2] 83 ae [2] ad ae [2] 92 b2 }

  condition:
    any of them
}