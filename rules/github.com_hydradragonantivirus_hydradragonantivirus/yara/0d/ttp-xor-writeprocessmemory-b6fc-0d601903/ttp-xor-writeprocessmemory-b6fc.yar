rule TTP_XOR_WriteProcessMemory_b6fc {
  strings:
    $key_b6fc = { e1 8e [2] d3 ac [2] d5 99 [2] fb 99 [2] c4 85 }

  condition:
    any of them
}