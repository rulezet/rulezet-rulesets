rule TTP_XOR_WriteProcessMemory_b63e {
  strings:
    $key_b63e = { e1 4c [2] d3 6e [2] d5 5b [2] fb 5b [2] c4 47 }

  condition:
    any of them
}