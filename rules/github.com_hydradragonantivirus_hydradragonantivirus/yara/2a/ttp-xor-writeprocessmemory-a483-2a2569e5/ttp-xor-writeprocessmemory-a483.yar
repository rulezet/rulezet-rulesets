rule TTP_XOR_WriteProcessMemory_a483 {
  strings:
    $key_a483 = { f3 f1 [2] c1 d3 [2] c7 e6 [2] e9 e6 [2] d6 fa }

  condition:
    any of them
}