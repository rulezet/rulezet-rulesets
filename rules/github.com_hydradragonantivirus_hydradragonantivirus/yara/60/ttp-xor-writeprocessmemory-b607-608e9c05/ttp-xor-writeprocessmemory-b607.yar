rule TTP_XOR_WriteProcessMemory_b607 {
  strings:
    $key_b607 = { e1 75 [2] d3 57 [2] d5 62 [2] fb 62 [2] c4 7e }

  condition:
    any of them
}