rule TTP_XOR_WriteProcessMemory_3dcb {
  strings:
    $key_3dcb = { 6a b9 [2] 58 9b [2] 5e ae [2] 70 ae [2] 4f b2 }

  condition:
    any of them
}