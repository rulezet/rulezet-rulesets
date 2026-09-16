rule TTP_XOR_WriteProcessMemory_b63d {
  strings:
    $key_b63d = { e1 4f [2] d3 6d [2] d5 58 [2] fb 58 [2] c4 44 }

  condition:
    any of them
}