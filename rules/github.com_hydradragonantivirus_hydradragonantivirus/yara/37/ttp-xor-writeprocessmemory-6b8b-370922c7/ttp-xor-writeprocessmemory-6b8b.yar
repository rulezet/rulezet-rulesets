rule TTP_XOR_WriteProcessMemory_6b8b {
  strings:
    $key_6b8b = { 3c f9 [2] 0e db [2] 08 ee [2] 26 ee [2] 19 f2 }

  condition:
    any of them
}