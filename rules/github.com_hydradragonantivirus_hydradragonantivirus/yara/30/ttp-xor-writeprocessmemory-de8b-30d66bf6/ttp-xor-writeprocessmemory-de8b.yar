rule TTP_XOR_WriteProcessMemory_de8b {
  strings:
    $key_de8b = { 89 f9 [2] bb db [2] bd ee [2] 93 ee [2] ac f2 }

  condition:
    any of them
}