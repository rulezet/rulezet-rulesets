rule TTP_XOR_WriteProcessMemory_c5cb {
  strings:
    $key_c5cb = { 92 b9 [2] a0 9b [2] a6 ae [2] 88 ae [2] b7 b2 }

  condition:
    any of them
}