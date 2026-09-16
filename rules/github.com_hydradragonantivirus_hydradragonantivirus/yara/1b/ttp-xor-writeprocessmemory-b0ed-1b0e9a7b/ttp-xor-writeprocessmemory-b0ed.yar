rule TTP_XOR_WriteProcessMemory_b0ed {
  strings:
    $key_b0ed = { e7 9f [2] d5 bd [2] d3 88 [2] fd 88 [2] c2 94 }

  condition:
    any of them
}