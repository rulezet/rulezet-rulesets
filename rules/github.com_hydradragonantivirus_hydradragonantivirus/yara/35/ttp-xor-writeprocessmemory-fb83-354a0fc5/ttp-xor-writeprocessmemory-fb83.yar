rule TTP_XOR_WriteProcessMemory_fb83 {
  strings:
    $key_fb83 = { ac f1 [2] 9e d3 [2] 98 e6 [2] b6 e6 [2] 89 fa }

  condition:
    any of them
}