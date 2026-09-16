rule TTP_XOR_WriteProcessMemory_0dcb {
  strings:
    $key_0dcb = { 5a b9 [2] 68 9b [2] 6e ae [2] 40 ae [2] 7f b2 }

  condition:
    any of them
}