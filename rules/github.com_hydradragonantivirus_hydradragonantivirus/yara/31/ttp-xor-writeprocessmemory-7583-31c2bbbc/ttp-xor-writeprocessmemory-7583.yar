rule TTP_XOR_WriteProcessMemory_7583 {
  strings:
    $key_7583 = { 22 f1 [2] 10 d3 [2] 16 e6 [2] 38 e6 [2] 07 fa }

  condition:
    any of them
}