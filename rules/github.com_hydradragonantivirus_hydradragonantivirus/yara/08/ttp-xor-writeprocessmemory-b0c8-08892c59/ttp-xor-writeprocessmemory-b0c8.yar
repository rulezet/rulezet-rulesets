rule TTP_XOR_WriteProcessMemory_b0c8 {
  strings:
    $key_b0c8 = { e7 ba [2] d5 98 [2] d3 ad [2] fd ad [2] c2 b1 }

  condition:
    any of them
}