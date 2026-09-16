rule TTP_XOR_WriteProcessMemory_83b6 {
  strings:
    $key_83b6 = { d4 c4 [2] e6 e6 [2] e0 d3 [2] ce d3 [2] f1 cf }

  condition:
    any of them
}