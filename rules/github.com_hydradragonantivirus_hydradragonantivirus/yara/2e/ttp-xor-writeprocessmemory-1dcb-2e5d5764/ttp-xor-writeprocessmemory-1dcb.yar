rule TTP_XOR_WriteProcessMemory_1dcb {
  strings:
    $key_1dcb = { 4a b9 [2] 78 9b [2] 7e ae [2] 50 ae [2] 6f b2 }

  condition:
    any of them
}