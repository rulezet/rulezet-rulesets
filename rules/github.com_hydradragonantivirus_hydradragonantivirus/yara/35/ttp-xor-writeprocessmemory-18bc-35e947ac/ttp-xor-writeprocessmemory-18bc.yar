rule TTP_XOR_WriteProcessMemory_18bc {
  strings:
    $key_18bc = { 4f ce [2] 7d ec [2] 7b d9 [2] 55 d9 [2] 6a c5 }

  condition:
    any of them
}