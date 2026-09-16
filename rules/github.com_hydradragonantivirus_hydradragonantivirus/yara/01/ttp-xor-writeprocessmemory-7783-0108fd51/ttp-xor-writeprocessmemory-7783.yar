rule TTP_XOR_WriteProcessMemory_7783 {
  strings:
    $key_7783 = { 20 f1 [2] 12 d3 [2] 14 e6 [2] 3a e6 [2] 05 fa }

  condition:
    any of them
}