rule TTP_XOR_WriteProcessMemory_638b {
  strings:
    $key_638b = { 34 f9 [2] 06 db [2] 00 ee [2] 2e ee [2] 11 f2 }

  condition:
    any of them
}