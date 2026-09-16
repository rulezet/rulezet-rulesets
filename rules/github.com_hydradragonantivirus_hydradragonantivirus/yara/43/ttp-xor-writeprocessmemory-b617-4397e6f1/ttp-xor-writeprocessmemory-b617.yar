rule TTP_XOR_WriteProcessMemory_b617 {
  strings:
    $key_b617 = { e1 65 [2] d3 47 [2] d5 72 [2] fb 72 [2] c4 6e }

  condition:
    any of them
}