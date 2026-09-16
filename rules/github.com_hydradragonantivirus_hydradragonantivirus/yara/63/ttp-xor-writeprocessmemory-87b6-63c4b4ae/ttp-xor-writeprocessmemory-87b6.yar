rule TTP_XOR_WriteProcessMemory_87b6 {
  strings:
    $key_87b6 = { d0 c4 [2] e2 e6 [2] e4 d3 [2] ca d3 [2] f5 cf }

  condition:
    any of them
}