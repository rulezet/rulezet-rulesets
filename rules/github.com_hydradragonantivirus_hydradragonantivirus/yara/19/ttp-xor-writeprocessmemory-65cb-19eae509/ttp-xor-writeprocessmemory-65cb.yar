rule TTP_XOR_WriteProcessMemory_65cb {
  strings:
    $key_65cb = { 32 b9 [2] 00 9b [2] 06 ae [2] 28 ae [2] 17 b2 }

  condition:
    any of them
}