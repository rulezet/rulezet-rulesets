rule TTP_XOR_WriteProcessMemory_c3cb {
  strings:
    $key_c3cb = { 94 b9 [2] a6 9b [2] a0 ae [2] 8e ae [2] b1 b2 }

  condition:
    any of them
}