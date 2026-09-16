rule TTP_XOR_WriteProcessMemory_b783 {
  strings:
    $key_b783 = { e0 f1 [2] d2 d3 [2] d4 e6 [2] fa e6 [2] c5 fa }

  condition:
    any of them
}