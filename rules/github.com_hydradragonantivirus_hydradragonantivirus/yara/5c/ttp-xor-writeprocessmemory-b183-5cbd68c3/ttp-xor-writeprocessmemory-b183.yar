rule TTP_XOR_WriteProcessMemory_b183 {
  strings:
    $key_b183 = { e6 f1 [2] d4 d3 [2] d2 e6 [2] fc e6 [2] c3 fa }

  condition:
    any of them
}