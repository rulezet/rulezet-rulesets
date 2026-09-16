rule TTP_XOR_WriteProcessMemory_7283 {
  strings:
    $key_7283 = { 25 f1 [2] 17 d3 [2] 11 e6 [2] 3f e6 [2] 00 fa }

  condition:
    any of them
}