rule TTP_XOR_WriteProcessMemory_b383 {
  strings:
    $key_b383 = { e4 f1 [2] d6 d3 [2] d0 e6 [2] fe e6 [2] c1 fa }

  condition:
    any of them
}