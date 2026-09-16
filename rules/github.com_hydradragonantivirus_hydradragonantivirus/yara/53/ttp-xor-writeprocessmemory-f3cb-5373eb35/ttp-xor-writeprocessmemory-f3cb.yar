rule TTP_XOR_WriteProcessMemory_f3cb {
  strings:
    $key_f3cb = { a4 b9 [2] 96 9b [2] 90 ae [2] be ae [2] 81 b2 }

  condition:
    any of them
}