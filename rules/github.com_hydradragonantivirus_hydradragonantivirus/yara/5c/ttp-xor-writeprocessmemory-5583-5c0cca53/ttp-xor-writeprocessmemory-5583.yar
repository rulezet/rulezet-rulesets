rule TTP_XOR_WriteProcessMemory_5583 {
  strings:
    $key_5583 = { 02 f1 [2] 30 d3 [2] 36 e6 [2] 18 e6 [2] 27 fa }

  condition:
    any of them
}