rule TTP_XOR_WriteProcessMemory_50cb {
  strings:
    $key_50cb = { 07 b9 [2] 35 9b [2] 33 ae [2] 1d ae [2] 22 b2 }

  condition:
    any of them
}