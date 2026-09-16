rule TTP_XOR_WriteProcessMemory_c283 {
  strings:
    $key_c283 = { 95 f1 [2] a7 d3 [2] a1 e6 [2] 8f e6 [2] b0 fa }

  condition:
    any of them
}