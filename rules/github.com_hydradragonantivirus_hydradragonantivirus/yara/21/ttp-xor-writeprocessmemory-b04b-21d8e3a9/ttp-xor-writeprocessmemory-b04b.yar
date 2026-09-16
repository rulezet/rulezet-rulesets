rule TTP_XOR_WriteProcessMemory_b04b {
  strings:
    $key_b04b = { e7 39 [2] d5 1b [2] d3 2e [2] fd 2e [2] c2 32 }

  condition:
    any of them
}