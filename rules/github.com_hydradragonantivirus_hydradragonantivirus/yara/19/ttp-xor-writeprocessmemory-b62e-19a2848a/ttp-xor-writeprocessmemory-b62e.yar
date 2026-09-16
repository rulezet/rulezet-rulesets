rule TTP_XOR_WriteProcessMemory_b62e {
  strings:
    $key_b62e = { e1 5c [2] d3 7e [2] d5 4b [2] fb 4b [2] c4 57 }

  condition:
    any of them
}