rule TTP_XOR_WriteProcessMemory_b0e9 {
  strings:
    $key_b0e9 = { e7 9b [2] d5 b9 [2] d3 8c [2] fd 8c [2] c2 90 }

  condition:
    any of them
}