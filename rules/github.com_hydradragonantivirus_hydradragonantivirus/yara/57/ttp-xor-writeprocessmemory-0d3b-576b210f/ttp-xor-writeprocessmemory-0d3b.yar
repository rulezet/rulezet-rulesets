rule TTP_XOR_WriteProcessMemory_0d3b {
  strings:
    $key_0d3b = { 5a 49 [2] 68 6b [2] 6e 5e [2] 40 5e [2] 7f 42 }

  condition:
    any of them
}