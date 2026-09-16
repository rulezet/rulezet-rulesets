rule TTP_XOR_WriteProcessMemory_d5cb {
  strings:
    $key_d5cb = { 82 b9 [2] b0 9b [2] b6 ae [2] 98 ae [2] a7 b2 }

  condition:
    any of them
}