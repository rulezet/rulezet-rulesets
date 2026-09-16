rule TTP_XOR_WriteProcessMemory_4dcb {
  strings:
    $key_4dcb = { 1a b9 [2] 28 9b [2] 2e ae [2] 00 ae [2] 3f b2 }

  condition:
    any of them
}