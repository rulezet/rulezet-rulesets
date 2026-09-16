rule TTP_XOR_WriteProcessMemory_b07d {
  strings:
    $key_b07d = { e7 0f [2] d5 2d [2] d3 18 [2] fd 18 [2] c2 04 }

  condition:
    any of them
}