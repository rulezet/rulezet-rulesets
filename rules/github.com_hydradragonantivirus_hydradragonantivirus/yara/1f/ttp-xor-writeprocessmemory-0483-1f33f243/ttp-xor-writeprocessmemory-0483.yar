rule TTP_XOR_WriteProcessMemory_0483 {
  strings:
    $key_0483 = { 53 f1 [2] 61 d3 [2] 67 e6 [2] 49 e6 [2] 76 fa }

  condition:
    any of them
}