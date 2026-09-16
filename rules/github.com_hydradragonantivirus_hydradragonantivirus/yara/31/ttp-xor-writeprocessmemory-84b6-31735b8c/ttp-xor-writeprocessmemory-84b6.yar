rule TTP_XOR_WriteProcessMemory_84b6 {
  strings:
    $key_84b6 = { d3 c4 [2] e1 e6 [2] e7 d3 [2] c9 d3 [2] f6 cf }

  condition:
    any of them
}