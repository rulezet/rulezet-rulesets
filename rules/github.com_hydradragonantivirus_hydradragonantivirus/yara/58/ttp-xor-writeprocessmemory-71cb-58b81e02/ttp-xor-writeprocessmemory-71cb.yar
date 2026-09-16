rule TTP_XOR_WriteProcessMemory_71cb {
  strings:
    $key_71cb = { 26 b9 [2] 14 9b [2] 12 ae [2] 3c ae [2] 03 b2 }

  condition:
    any of them
}