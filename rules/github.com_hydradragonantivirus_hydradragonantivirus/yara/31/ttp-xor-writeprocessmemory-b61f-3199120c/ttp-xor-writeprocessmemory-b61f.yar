rule TTP_XOR_WriteProcessMemory_b61f {
  strings:
    $key_b61f = { e1 6d [2] d3 4f [2] d5 7a [2] fb 7a [2] c4 66 }

  condition:
    any of them
}