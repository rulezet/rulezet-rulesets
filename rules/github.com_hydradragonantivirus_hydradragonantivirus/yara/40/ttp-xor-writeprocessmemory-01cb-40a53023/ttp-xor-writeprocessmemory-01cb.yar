rule TTP_XOR_WriteProcessMemory_01cb {
  strings:
    $key_01cb = { 56 b9 [2] 64 9b [2] 62 ae [2] 4c ae [2] 73 b2 }

  condition:
    any of them
}