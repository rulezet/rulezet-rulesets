rule TTP_XOR_WriteProcessMemory_b002 {
  strings:
    $key_b002 = { e7 70 [2] d5 52 [2] d3 67 [2] fd 67 [2] c2 7b }

  condition:
    any of them
}