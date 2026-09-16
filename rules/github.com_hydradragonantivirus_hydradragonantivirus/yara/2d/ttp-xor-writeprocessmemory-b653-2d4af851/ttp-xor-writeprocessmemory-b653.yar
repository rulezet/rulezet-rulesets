rule TTP_XOR_WriteProcessMemory_b653 {
  strings:
    $key_b653 = { e1 21 [2] d3 03 [2] d5 36 [2] fb 36 [2] c4 2a }

  condition:
    any of them
}