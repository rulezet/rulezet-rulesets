rule TTP_XOR_WriteProcessMemory_b03d {
  strings:
    $key_b03d = { e7 4f [2] d5 6d [2] d3 58 [2] fd 58 [2] c2 44 }

  condition:
    any of them
}