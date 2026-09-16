rule TTP_XOR_WriteProcessMemory_8183 {
  strings:
    $key_8183 = { d6 f1 [2] e4 d3 [2] e2 e6 [2] cc e6 [2] f3 fa }

  condition:
    any of them
}