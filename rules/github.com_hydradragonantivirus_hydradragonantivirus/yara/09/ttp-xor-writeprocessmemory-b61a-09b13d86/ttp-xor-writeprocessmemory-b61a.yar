rule TTP_XOR_WriteProcessMemory_b61a {
  strings:
    $key_b61a = { e1 68 [2] d3 4a [2] d5 7f [2] fb 7f [2] c4 63 }

  condition:
    any of them
}