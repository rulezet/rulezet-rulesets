rule TTP_XOR_WriteProcessMemory_0a8b {
  strings:
    $key_0a8b = { 5d f9 [2] 6f db [2] 69 ee [2] 47 ee [2] 78 f2 }

  condition:
    any of them
}