rule TTP_XOR_WriteProcessMemory_b008 {
  strings:
    $key_b008 = { e7 7a [2] d5 58 [2] d3 6d [2] fd 6d [2] c2 71 }

  condition:
    any of them
}