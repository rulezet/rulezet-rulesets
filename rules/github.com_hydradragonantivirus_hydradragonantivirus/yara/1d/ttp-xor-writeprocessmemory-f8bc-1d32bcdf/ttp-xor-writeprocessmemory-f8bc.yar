rule TTP_XOR_WriteProcessMemory_f8bc {
  strings:
    $key_f8bc = { af ce [2] 9d ec [2] 9b d9 [2] b5 d9 [2] 8a c5 }

  condition:
    any of them
}