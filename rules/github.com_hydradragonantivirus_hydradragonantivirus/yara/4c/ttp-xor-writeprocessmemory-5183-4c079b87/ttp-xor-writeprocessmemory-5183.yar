rule TTP_XOR_WriteProcessMemory_5183 {
  strings:
    $key_5183 = { 06 f1 [2] 34 d3 [2] 32 e6 [2] 1c e6 [2] 23 fa }

  condition:
    any of them
}