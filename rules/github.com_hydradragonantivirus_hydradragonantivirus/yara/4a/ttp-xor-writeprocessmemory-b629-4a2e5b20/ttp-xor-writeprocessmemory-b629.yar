rule TTP_XOR_WriteProcessMemory_b629 {
  strings:
    $key_b629 = { e1 5b [2] d3 79 [2] d5 4c [2] fb 4c [2] c4 50 }

  condition:
    any of them
}