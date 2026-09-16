rule TTP_XOR_WriteProcessMemory_778b {
  strings:
    $key_778b = { 20 f9 [2] 12 db [2] 14 ee [2] 3a ee [2] 05 f2 }

  condition:
    any of them
}