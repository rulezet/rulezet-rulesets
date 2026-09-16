rule TTP_XOR_WriteProcessMemory_15cb {
  strings:
    $key_15cb = { 42 b9 [2] 70 9b [2] 76 ae [2] 58 ae [2] 67 b2 }

  condition:
    any of them
}