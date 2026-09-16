rule TTP_XOR_WriteProcessMemory_b60d {
  strings:
    $key_b60d = { e1 7f [2] d3 5d [2] d5 68 [2] fb 68 [2] c4 74 }

  condition:
    any of them
}