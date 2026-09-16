rule TTP_XOR_WriteProcessMemory_b03f {
  strings:
    $key_b03f = { e7 4d [2] d5 6f [2] d3 5a [2] fd 5a [2] c2 46 }

  condition:
    any of them
}