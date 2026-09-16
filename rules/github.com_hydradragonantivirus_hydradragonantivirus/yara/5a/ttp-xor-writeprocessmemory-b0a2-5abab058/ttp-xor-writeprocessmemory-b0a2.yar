rule TTP_XOR_WriteProcessMemory_b0a2 {
  strings:
    $key_b0a2 = { e7 d0 [2] d5 f2 [2] d3 c7 [2] fd c7 [2] c2 db }

  condition:
    any of them
}