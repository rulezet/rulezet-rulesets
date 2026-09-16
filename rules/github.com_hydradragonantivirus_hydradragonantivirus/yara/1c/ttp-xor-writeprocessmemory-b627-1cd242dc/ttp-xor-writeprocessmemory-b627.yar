rule TTP_XOR_WriteProcessMemory_b627 {
  strings:
    $key_b627 = { e1 55 [2] d3 77 [2] d5 42 [2] fb 42 [2] c4 5e }

  condition:
    any of them
}