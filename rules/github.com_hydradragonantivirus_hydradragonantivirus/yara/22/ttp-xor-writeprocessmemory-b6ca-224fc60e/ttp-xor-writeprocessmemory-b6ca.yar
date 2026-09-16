rule TTP_XOR_WriteProcessMemory_b6ca {
  strings:
    $key_b6ca = { e1 b8 [2] d3 9a [2] d5 af [2] fb af [2] c4 b3 }

  condition:
    any of them
}