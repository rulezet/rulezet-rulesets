rule TTP_XOR_WriteProcessMemory_8eb6 {
  strings:
    $key_8eb6 = { d9 c4 [2] eb e6 [2] ed d3 [2] c3 d3 [2] fc cf }

  condition:
    any of them
}