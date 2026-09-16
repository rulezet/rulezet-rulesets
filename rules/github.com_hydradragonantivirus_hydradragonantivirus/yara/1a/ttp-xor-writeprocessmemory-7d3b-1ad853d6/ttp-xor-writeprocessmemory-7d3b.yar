rule TTP_XOR_WriteProcessMemory_7d3b {
  strings:
    $key_7d3b = { 2a 49 [2] 18 6b [2] 1e 5e [2] 30 5e [2] 0f 42 }

  condition:
    any of them
}