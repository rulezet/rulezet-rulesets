rule TTP_XOR_WriteProcessMemory_278b {
  strings:
    $key_278b = { 70 f9 [2] 42 db [2] 44 ee [2] 6a ee [2] 55 f2 }

  condition:
    any of them
}