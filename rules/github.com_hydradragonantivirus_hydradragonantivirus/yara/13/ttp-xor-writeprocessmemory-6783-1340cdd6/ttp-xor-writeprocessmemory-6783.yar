rule TTP_XOR_WriteProcessMemory_6783 {
  strings:
    $key_6783 = { 30 f1 [2] 02 d3 [2] 04 e6 [2] 2a e6 [2] 15 fa }

  condition:
    any of them
}