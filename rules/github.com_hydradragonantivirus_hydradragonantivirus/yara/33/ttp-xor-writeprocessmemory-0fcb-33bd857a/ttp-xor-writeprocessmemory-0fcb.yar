rule TTP_XOR_WriteProcessMemory_0fcb {
  strings:
    $key_0fcb = { 58 b9 [2] 6a 9b [2] 6c ae [2] 42 ae [2] 7d b2 }

  condition:
    any of them
}