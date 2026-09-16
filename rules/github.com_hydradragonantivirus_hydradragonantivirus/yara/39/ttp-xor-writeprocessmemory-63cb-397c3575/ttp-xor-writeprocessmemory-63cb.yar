rule TTP_XOR_WriteProcessMemory_63cb {
  strings:
    $key_63cb = { 34 b9 [2] 06 9b [2] 00 ae [2] 2e ae [2] 11 b2 }

  condition:
    any of them
}