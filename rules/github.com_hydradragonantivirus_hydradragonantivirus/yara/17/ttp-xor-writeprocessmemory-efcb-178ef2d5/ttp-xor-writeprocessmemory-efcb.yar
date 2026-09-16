rule TTP_XOR_WriteProcessMemory_efcb {
  strings:
    $key_efcb = { b8 b9 [2] 8a 9b [2] 8c ae [2] a2 ae [2] 9d b2 }

  condition:
    any of them
}