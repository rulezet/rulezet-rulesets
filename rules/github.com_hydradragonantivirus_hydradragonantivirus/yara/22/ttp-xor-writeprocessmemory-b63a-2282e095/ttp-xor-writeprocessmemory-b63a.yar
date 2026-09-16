rule TTP_XOR_WriteProcessMemory_b63a {
  strings:
    $key_b63a = { e1 48 [2] d3 6a [2] d5 5f [2] fb 5f [2] c4 43 }

  condition:
    any of them
}