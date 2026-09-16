rule TTP_XOR_WriteProcessMemory_b694 {
  strings:
    $key_b694 = { e1 e6 [2] d3 c4 [2] d5 f1 [2] fb f1 [2] c4 ed }

  condition:
    any of them
}