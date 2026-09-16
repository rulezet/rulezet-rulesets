rule TTP_XOR_WriteProcessMemory_b00f {
  strings:
    $key_b00f = { e7 7d [2] d5 5f [2] d3 6a [2] fd 6a [2] c2 76 }

  condition:
    any of them
}