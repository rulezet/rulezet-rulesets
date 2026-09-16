rule TTP_XOR_WriteProcessMemory_b05f {
  strings:
    $key_b05f = { e7 2d [2] d5 0f [2] d3 3a [2] fd 3a [2] c2 26 }

  condition:
    any of them
}