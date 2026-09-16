rule TTP_XOR_WriteProcessMemory_b028 {
  strings:
    $key_b028 = { e7 5a [2] d5 78 [2] d3 4d [2] fd 4d [2] c2 51 }

  condition:
    any of them
}