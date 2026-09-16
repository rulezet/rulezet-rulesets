rule TTP_XOR_WriteProcessMemory_7fb6 {
  strings:
    $key_7fb6 = { 28 c4 [2] 1a e6 [2] 1c d3 [2] 32 d3 [2] 0d cf }

  condition:
    any of them
}