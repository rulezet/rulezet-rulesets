rule TTP_XOR_WriteProcessMemory_268b {
  strings:
    $key_268b = { 71 f9 [2] 43 db [2] 45 ee [2] 6b ee [2] 54 f2 }

  condition:
    any of them
}