rule TTP_XOR_WriteProcessMemory_b00a {
  strings:
    $key_b00a = { e7 78 [2] d5 5a [2] d3 6f [2] fd 6f [2] c2 73 }

  condition:
    any of them
}