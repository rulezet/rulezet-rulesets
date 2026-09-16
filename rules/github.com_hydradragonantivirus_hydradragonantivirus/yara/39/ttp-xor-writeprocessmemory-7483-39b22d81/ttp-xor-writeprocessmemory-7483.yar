rule TTP_XOR_WriteProcessMemory_7483 {
  strings:
    $key_7483 = { 23 f1 [2] 11 d3 [2] 17 e6 [2] 39 e6 [2] 06 fa }

  condition:
    any of them
}