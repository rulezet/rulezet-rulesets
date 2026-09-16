rule TTP_XOR_WriteProcessMemory_b0ca {
  strings:
    $key_b0ca = { e7 b8 [2] d5 9a [2] d3 af [2] fd af [2] c2 b3 }

  condition:
    any of them
}