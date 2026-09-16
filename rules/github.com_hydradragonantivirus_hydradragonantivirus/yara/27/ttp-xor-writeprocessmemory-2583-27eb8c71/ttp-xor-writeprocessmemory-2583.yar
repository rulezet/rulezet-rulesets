rule TTP_XOR_WriteProcessMemory_2583 {
  strings:
    $key_2583 = { 72 f1 [2] 40 d3 [2] 46 e6 [2] 68 e6 [2] 57 fa }

  condition:
    any of them
}