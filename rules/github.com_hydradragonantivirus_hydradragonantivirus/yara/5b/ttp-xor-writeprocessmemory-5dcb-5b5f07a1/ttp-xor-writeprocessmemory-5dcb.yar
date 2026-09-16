rule TTP_XOR_WriteProcessMemory_5dcb {
  strings:
    $key_5dcb = { 0a b9 [2] 38 9b [2] 3e ae [2] 10 ae [2] 2f b2 }

  condition:
    any of them
}