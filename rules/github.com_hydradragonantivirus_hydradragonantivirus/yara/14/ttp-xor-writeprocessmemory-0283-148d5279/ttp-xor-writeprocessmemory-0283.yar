rule TTP_XOR_WriteProcessMemory_0283 {
  strings:
    $key_0283 = { 55 f1 [2] 67 d3 [2] 61 e6 [2] 4f e6 [2] 70 fa }

  condition:
    any of them
}