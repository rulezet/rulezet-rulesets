rule TTP_XOR_WriteProcessMemory_14cb {
  strings:
    $key_14cb = { 43 b9 [2] 71 9b [2] 77 ae [2] 59 ae [2] 66 b2 }

  condition:
    any of them
}