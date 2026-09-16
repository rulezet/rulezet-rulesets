rule TTP_XOR_WriteProcessMemory_b688 {
  strings:
    $key_b688 = { e1 fa [2] d3 d8 [2] d5 ed [2] fb ed [2] c4 f1 }

  condition:
    any of them
}