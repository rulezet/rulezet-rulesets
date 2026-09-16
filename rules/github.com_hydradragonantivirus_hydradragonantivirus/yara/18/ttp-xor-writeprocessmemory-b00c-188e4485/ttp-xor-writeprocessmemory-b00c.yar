rule TTP_XOR_WriteProcessMemory_b00c {
  strings:
    $key_b00c = { e7 7e [2] d5 5c [2] d3 69 [2] fd 69 [2] c2 75 }

  condition:
    any of them
}