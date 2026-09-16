rule TTP_XOR_WriteProcessMemory_c1cb {
  strings:
    $key_c1cb = { 96 b9 [2] a4 9b [2] a2 ae [2] 8c ae [2] b3 b2 }

  condition:
    any of them
}