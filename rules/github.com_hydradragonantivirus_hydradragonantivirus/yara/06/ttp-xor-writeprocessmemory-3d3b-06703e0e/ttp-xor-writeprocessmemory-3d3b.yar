rule TTP_XOR_WriteProcessMemory_3d3b {
  strings:
    $key_3d3b = { 6a 49 [2] 58 6b [2] 5e 5e [2] 70 5e [2] 4f 42 }

  condition:
    any of them
}