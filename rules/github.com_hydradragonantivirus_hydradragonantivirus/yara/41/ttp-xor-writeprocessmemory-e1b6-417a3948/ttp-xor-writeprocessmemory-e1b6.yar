rule TTP_XOR_WriteProcessMemory_e1b6 {
  strings:
    $key_e1b6 = { b6 c4 [2] 84 e6 [2] 82 d3 [2] ac d3 [2] 93 cf }

  condition:
    any of them
}