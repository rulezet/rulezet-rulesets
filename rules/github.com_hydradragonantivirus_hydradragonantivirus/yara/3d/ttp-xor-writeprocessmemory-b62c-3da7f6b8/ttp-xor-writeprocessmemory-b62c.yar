rule TTP_XOR_WriteProcessMemory_b62c {
  strings:
    $key_b62c = { e1 5e [2] d3 7c [2] d5 49 [2] fb 49 [2] c4 55 }

  condition:
    any of them
}