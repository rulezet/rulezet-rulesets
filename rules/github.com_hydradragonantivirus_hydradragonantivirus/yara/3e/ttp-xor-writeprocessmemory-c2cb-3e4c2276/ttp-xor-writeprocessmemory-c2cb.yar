rule TTP_XOR_WriteProcessMemory_c2cb {
  strings:
    $key_c2cb = { 95 b9 [2] a7 9b [2] a1 ae [2] 8f ae [2] b0 b2 }

  condition:
    any of them
}