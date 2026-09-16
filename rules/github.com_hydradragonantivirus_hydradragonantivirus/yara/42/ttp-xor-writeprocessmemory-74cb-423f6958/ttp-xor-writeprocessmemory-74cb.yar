rule TTP_XOR_WriteProcessMemory_74cb {
  strings:
    $key_74cb = { 23 b9 [2] 11 9b [2] 17 ae [2] 39 ae [2] 06 b2 }

  condition:
    any of them
}