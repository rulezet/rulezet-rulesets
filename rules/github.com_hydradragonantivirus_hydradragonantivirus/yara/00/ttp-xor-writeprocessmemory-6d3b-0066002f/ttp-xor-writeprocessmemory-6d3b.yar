rule TTP_XOR_WriteProcessMemory_6d3b {
  strings:
    $key_6d3b = { 3a 49 [2] 08 6b [2] 0e 5e [2] 20 5e [2] 1f 42 }

  condition:
    any of them
}