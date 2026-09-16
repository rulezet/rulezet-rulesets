rule TTP_XOR_WriteProcessMemory_10cb {
  strings:
    $key_10cb = { 47 b9 [2] 75 9b [2] 73 ae [2] 5d ae [2] 62 b2 }

  condition:
    any of them
}