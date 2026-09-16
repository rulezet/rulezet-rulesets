rule TTP_XOR_WriteProcessMemory_e8bc {
  strings:
    $key_e8bc = { bf ce [2] 8d ec [2] 8b d9 [2] a5 d9 [2] 9a c5 }

  condition:
    any of them
}