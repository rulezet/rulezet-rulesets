rule TTP_XOR_WriteProcessMemory_8bb6 {
  strings:
    $key_8bb6 = { dc c4 [2] ee e6 [2] e8 d3 [2] c6 d3 [2] f9 cf }

  condition:
    any of them
}