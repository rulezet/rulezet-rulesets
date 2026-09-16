rule TTP_XOR_WriteProcessMemory_b605 {
  strings:
    $key_b605 = { e1 77 [2] d3 55 [2] d5 60 [2] fb 60 [2] c4 7c }

  condition:
    any of them
}