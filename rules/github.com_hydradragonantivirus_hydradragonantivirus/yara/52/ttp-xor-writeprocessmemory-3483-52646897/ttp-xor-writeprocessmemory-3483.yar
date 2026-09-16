rule TTP_XOR_WriteProcessMemory_3483 {
  strings:
    $key_3483 = { 63 f1 [2] 51 d3 [2] 57 e6 [2] 79 e6 [2] 46 fa }

  condition:
    any of them
}