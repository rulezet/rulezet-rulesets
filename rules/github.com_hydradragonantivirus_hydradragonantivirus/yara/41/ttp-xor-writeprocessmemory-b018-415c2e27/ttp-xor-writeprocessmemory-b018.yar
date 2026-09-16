rule TTP_XOR_WriteProcessMemory_b018 {
  strings:
    $key_b018 = { e7 6a [2] d5 48 [2] d3 7d [2] fd 7d [2] c2 61 }

  condition:
    any of them
}