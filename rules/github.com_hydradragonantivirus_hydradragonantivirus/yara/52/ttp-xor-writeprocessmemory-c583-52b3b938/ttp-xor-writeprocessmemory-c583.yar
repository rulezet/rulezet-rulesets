rule TTP_XOR_WriteProcessMemory_c583 {
  strings:
    $key_c583 = { 92 f1 [2] a0 d3 [2] a6 e6 [2] 88 e6 [2] b7 fa }

  condition:
    any of them
}