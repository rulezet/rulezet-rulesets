rule TTP_XOR_WriteProcessMemory_b6e8 {
  strings:
    $key_b6e8 = { e1 9a [2] d3 b8 [2] d5 8d [2] fb 8d [2] c4 91 }

  condition:
    any of them
}