rule TTP_XOR_WriteProcessMemory_b65d {
  strings:
    $key_b65d = { e1 2f [2] d3 0d [2] d5 38 [2] fb 38 [2] c4 24 }

  condition:
    any of them
}