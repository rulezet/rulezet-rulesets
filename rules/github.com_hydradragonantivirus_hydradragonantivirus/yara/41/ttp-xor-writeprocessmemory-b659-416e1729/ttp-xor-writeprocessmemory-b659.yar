rule TTP_XOR_WriteProcessMemory_b659 {
  strings:
    $key_b659 = { e1 2b [2] d3 09 [2] d5 3c [2] fb 3c [2] c4 20 }

  condition:
    any of them
}