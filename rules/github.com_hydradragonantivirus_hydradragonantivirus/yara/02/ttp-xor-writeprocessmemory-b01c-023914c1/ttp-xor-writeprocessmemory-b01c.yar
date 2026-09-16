rule TTP_XOR_WriteProcessMemory_b01c {
  strings:
    $key_b01c = { e7 6e [2] d5 4c [2] d3 79 [2] fd 79 [2] c2 65 }

  condition:
    any of them
}