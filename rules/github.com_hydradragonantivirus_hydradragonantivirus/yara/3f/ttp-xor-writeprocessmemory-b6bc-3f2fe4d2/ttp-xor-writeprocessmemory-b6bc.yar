rule TTP_XOR_WriteProcessMemory_b6bc {
  strings:
    $key_b6bc = { e1 ce [2] d3 ec [2] d5 d9 [2] fb d9 [2] c4 c5 }

  condition:
    any of them
}