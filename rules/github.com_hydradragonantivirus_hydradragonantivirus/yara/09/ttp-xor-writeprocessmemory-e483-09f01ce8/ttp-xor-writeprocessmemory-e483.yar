rule TTP_XOR_WriteProcessMemory_e483 {
  strings:
    $key_e483 = { b3 f1 [2] 81 d3 [2] 87 e6 [2] a9 e6 [2] 96 fa }

  condition:
    any of them
}