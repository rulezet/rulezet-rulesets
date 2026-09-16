rule TTP_XOR_WriteProcessMemory_b068 {
  strings:
    $key_b068 = { e7 1a [2] d5 38 [2] d3 0d [2] fd 0d [2] c2 11 }

  condition:
    any of them
}