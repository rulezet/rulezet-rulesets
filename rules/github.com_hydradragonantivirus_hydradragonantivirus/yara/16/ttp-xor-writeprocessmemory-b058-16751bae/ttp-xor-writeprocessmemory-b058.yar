rule TTP_XOR_WriteProcessMemory_b058 {
  strings:
    $key_b058 = { e7 2a [2] d5 08 [2] d3 3d [2] fd 3d [2] c2 21 }

  condition:
    any of them
}