rule TTP_XOR_WriteProcessMemory_4783 {
  strings:
    $key_4783 = { 10 f1 [2] 22 d3 [2] 24 e6 [2] 0a e6 [2] 35 fa }

  condition:
    any of them
}