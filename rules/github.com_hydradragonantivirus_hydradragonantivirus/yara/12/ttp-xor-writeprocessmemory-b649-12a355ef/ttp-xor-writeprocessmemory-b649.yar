rule TTP_XOR_WriteProcessMemory_b649 {
  strings:
    $key_b649 = { e1 3b [2] d3 19 [2] d5 2c [2] fb 2c [2] c4 30 }

  condition:
    any of them
}