rule TTP_XOR_WriteProcessMemory_b032 {
  strings:
    $key_b032 = { e7 40 [2] d5 62 [2] d3 57 [2] fd 57 [2] c2 4b }

  condition:
    any of them
}