rule TTP_XOR_WriteProcessMemory_b025 {
  strings:
    $key_b025 = { e7 57 [2] d5 75 [2] d3 40 [2] fd 40 [2] c2 5c }

  condition:
    any of them
}