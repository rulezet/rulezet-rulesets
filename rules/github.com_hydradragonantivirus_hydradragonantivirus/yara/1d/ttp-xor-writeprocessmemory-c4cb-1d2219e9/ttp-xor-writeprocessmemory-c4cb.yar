rule TTP_XOR_WriteProcessMemory_c4cb {
  strings:
    $key_c4cb = { 93 b9 [2] a1 9b [2] a7 ae [2] 89 ae [2] b6 b2 }

  condition:
    any of them
}