rule TTP_XOR_WriteProcessMemory_b6f8 {
  strings:
    $key_b6f8 = { e1 8a [2] d3 a8 [2] d5 9d [2] fb 9d [2] c4 81 }

  condition:
    any of them
}