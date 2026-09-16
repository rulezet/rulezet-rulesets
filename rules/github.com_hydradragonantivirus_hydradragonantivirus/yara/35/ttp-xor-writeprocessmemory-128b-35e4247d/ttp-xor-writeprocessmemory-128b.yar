rule TTP_XOR_WriteProcessMemory_128b {
  strings:
    $key_128b = { 45 f9 [2] 77 db [2] 71 ee [2] 5f ee [2] 60 f2 }

  condition:
    any of them
}