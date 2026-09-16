rule TTP_XOR_WriteProcessMemory_b640 {
  strings:
    $key_b640 = { e1 32 [2] d3 10 [2] d5 25 [2] fb 25 [2] c4 39 }

  condition:
    any of them
}