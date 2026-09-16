rule TTP_XOR_WriteProcessMemory_6fcb {
  strings:
    $key_6fcb = { 38 b9 [2] 0a 9b [2] 0c ae [2] 22 ae [2] 1d b2 }

  condition:
    any of them
}