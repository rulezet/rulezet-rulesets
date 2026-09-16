rule TTP_XOR_WriteProcessMemory_b3bc {
  strings:
    $key_b3bc = { e4 ce [2] d6 ec [2] d0 d9 [2] fe d9 [2] c1 c5 }

  condition:
    any of them
}