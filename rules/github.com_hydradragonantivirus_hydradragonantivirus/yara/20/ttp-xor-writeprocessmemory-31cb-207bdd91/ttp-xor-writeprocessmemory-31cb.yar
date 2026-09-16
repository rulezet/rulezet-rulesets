rule TTP_XOR_WriteProcessMemory_31cb {
  strings:
    $key_31cb = { 66 b9 [2] 54 9b [2] 52 ae [2] 7c ae [2] 43 b2 }

  condition:
    any of them
}