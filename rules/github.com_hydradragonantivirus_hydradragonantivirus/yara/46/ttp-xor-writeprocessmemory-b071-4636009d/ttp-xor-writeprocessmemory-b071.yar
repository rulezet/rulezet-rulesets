rule TTP_XOR_WriteProcessMemory_b071 {
  strings:
    $key_b071 = { e7 03 [2] d5 21 [2] d3 14 [2] fd 14 [2] c2 08 }

  condition:
    any of them
}