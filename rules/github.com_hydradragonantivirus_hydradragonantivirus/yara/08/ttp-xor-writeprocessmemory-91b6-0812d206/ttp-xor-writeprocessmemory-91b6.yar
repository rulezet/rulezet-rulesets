rule TTP_XOR_WriteProcessMemory_91b6 {
  strings:
    $key_91b6 = { c6 c4 [2] f4 e6 [2] f2 d3 [2] dc d3 [2] e3 cf }

  condition:
    any of them
}