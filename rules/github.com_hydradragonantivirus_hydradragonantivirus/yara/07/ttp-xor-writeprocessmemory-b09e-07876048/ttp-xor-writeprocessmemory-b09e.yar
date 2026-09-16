rule TTP_XOR_WriteProcessMemory_b09e {
  strings:
    $key_b09e = { e7 ec [2] d5 ce [2] d3 fb [2] fd fb [2] c2 e7 }

  condition:
    any of them
}