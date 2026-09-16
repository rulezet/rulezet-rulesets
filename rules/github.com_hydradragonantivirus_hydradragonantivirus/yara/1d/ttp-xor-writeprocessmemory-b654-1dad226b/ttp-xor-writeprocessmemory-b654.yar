rule TTP_XOR_WriteProcessMemory_b654 {
  strings:
    $key_b654 = { e1 26 [2] d3 04 [2] d5 31 [2] fb 31 [2] c4 2d }

  condition:
    any of them
}