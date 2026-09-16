rule TTP_XOR_WriteProcessMemory_b4b6 {
  strings:
    $key_b4b6 = { e3 c4 [2] d1 e6 [2] d7 d3 [2] f9 d3 [2] c6 cf }

  condition:
    any of them
}