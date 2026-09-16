rule TTP_XOR_WriteProcessMemory_f8cb {
  strings:
    $key_f8cb = { af b9 [2] 9d 9b [2] 9b ae [2] b5 ae [2] 8a b2 }

  condition:
    any of them
}