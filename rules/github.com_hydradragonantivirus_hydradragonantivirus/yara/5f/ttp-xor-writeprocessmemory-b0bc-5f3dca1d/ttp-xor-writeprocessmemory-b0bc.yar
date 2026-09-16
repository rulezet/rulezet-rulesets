rule TTP_XOR_WriteProcessMemory_b0bc {
  strings:
    $key_b0bc = { e7 ce [2] d5 ec [2] d3 d9 [2] fd d9 [2] c2 c5 }

  condition:
    any of them
}