rule TTP_XOR_WriteProcessMemory_b06c {
  strings:
    $key_b06c = { e7 1e [2] d5 3c [2] d3 09 [2] fd 09 [2] c2 15 }

  condition:
    any of them
}