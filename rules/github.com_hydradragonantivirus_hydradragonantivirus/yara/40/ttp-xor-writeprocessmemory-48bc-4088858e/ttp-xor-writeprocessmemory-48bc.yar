rule TTP_XOR_WriteProcessMemory_48bc {
  strings:
    $key_48bc = { 1f ce [2] 2d ec [2] 2b d9 [2] 05 d9 [2] 3a c5 }

  condition:
    any of them
}