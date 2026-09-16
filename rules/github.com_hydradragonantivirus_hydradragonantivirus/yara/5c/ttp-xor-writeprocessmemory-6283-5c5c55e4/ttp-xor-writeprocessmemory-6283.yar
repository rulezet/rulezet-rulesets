rule TTP_XOR_WriteProcessMemory_6283 {
  strings:
    $key_6283 = { 35 f1 [2] 07 d3 [2] 01 e6 [2] 2f e6 [2] 10 fa }

  condition:
    any of them
}