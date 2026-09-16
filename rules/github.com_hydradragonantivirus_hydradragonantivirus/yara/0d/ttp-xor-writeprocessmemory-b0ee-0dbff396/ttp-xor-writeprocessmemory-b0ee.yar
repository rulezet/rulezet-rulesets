rule TTP_XOR_WriteProcessMemory_b0ee {
  strings:
    $key_b0ee = { e7 9c [2] d5 be [2] d3 8b [2] fd 8b [2] c2 97 }

  condition:
    any of them
}