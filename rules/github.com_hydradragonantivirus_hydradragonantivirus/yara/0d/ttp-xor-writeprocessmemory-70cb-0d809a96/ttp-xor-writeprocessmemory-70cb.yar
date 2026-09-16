rule TTP_XOR_WriteProcessMemory_70cb {
  strings:
    $key_70cb = { 27 b9 [2] 15 9b [2] 13 ae [2] 3d ae [2] 02 b2 }

  condition:
    any of them
}