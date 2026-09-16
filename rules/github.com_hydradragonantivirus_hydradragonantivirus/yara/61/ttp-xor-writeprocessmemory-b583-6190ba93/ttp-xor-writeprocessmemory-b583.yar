rule TTP_XOR_WriteProcessMemory_b583 {
  strings:
    $key_b583 = { e2 f1 [2] d0 d3 [2] d6 e6 [2] f8 e6 [2] c7 fa }

  condition:
    any of them
}