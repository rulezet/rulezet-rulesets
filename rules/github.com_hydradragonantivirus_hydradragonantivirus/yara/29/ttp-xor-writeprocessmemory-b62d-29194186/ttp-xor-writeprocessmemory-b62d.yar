rule TTP_XOR_WriteProcessMemory_b62d {
  strings:
    $key_b62d = { e1 5f [2] d3 7d [2] d5 48 [2] fb 48 [2] c4 54 }

  condition:
    any of them
}