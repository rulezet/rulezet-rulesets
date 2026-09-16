rule TTP_XOR_WriteProcessMemory_d3bc {
  strings:
    $key_d3bc = { 84 ce [2] b6 ec [2] b0 d9 [2] 9e d9 [2] a1 c5 }

  condition:
    any of them
}