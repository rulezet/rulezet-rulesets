rule TTP_XOR_WriteProcessMemory_b05c {
  strings:
    $key_b05c = { e7 2e [2] d5 0c [2] d3 39 [2] fd 39 [2] c2 25 }

  condition:
    any of them
}