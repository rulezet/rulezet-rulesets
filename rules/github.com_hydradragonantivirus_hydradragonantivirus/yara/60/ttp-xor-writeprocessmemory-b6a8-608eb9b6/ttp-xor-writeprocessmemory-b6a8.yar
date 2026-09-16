rule TTP_XOR_WriteProcessMemory_b6a8 {
  strings:
    $key_b6a8 = { e1 da [2] d3 f8 [2] d5 cd [2] fb cd [2] c4 d1 }

  condition:
    any of them
}