rule TTP_XOR_WriteProcessMemory_b05a {
  strings:
    $key_b05a = { e7 28 [2] d5 0a [2] d3 3f [2] fd 3f [2] c2 23 }

  condition:
    any of them
}