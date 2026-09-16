rule TTP_XOR_WriteProcessMemory_b007 {
  strings:
    $key_b007 = { e7 75 [2] d5 57 [2] d3 62 [2] fd 62 [2] c2 7e }

  condition:
    any of them
}