rule TTP_XOR_WriteProcessMemory_b65e {
  strings:
    $key_b65e = { e1 2c [2] d3 0e [2] d5 3b [2] fb 3b [2] c4 27 }

  condition:
    any of them
}