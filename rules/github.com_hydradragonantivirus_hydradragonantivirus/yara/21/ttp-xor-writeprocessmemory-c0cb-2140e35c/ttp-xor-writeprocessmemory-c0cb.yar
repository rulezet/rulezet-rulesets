rule TTP_XOR_WriteProcessMemory_c0cb {
  strings:
    $key_c0cb = { 97 b9 [2] a5 9b [2] a3 ae [2] 8d ae [2] b2 b2 }

  condition:
    any of them
}