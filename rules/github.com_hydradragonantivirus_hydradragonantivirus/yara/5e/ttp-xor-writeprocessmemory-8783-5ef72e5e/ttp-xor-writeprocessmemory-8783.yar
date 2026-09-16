rule TTP_XOR_WriteProcessMemory_8783 {
  strings:
    $key_8783 = { d0 f1 [2] e2 d3 [2] e4 e6 [2] ca e6 [2] f5 fa }

  condition:
    any of them
}