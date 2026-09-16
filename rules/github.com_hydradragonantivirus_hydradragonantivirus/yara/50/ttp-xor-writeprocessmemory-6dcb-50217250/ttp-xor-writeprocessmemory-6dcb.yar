rule TTP_XOR_WriteProcessMemory_6dcb {
  strings:
    $key_6dcb = { 3a b9 [2] 08 9b [2] 0e ae [2] 20 ae [2] 1f b2 }

  condition:
    any of them
}