rule TTP_XOR_WriteProcessMemory_b07a {
  strings:
    $key_b07a = { e7 08 [2] d5 2a [2] d3 1f [2] fd 1f [2] c2 03 }

  condition:
    any of them
}