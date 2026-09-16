rule TTP_XOR_WriteProcessMemory_55cb {
  strings:
    $key_55cb = { 02 b9 [2] 30 9b [2] 36 ae [2] 18 ae [2] 27 b2 }

  condition:
    any of them
}