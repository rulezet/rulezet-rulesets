rule TTP_XOR_WriteProcessMemory_b613 {
  strings:
    $key_b613 = { e1 61 [2] d3 43 [2] d5 76 [2] fb 76 [2] c4 6a }

  condition:
    any of them
}