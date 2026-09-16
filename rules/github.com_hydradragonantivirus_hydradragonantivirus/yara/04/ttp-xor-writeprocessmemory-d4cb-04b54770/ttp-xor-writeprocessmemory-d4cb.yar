rule TTP_XOR_WriteProcessMemory_d4cb {
  strings:
    $key_d4cb = { 83 b9 [2] b1 9b [2] b7 ae [2] 99 ae [2] a6 b2 }

  condition:
    any of them
}