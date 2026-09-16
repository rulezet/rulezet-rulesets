rule TTP_XOR_WriteProcessMemory_a0b6 {
  strings:
    $key_a0b6 = { f7 c4 [2] c5 e6 [2] c3 d3 [2] ed d3 [2] d2 cf }

  condition:
    any of them
}