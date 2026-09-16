rule TTP_XOR_WriteProcessMemory_44cb {
  strings:
    $key_44cb = { 13 b9 [2] 21 9b [2] 27 ae [2] 09 ae [2] 36 b2 }

  condition:
    any of them
}