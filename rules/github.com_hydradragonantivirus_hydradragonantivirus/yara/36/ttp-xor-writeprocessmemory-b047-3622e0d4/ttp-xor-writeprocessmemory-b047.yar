rule TTP_XOR_WriteProcessMemory_b047 {
  strings:
    $key_b047 = { e7 35 [2] d5 17 [2] d3 22 [2] fd 22 [2] c2 3e }

  condition:
    any of them
}