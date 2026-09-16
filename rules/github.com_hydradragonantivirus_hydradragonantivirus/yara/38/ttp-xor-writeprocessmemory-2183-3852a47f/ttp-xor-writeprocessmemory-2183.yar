rule TTP_XOR_WriteProcessMemory_2183 {
  strings:
    $key_2183 = { 76 f1 [2] 44 d3 [2] 42 e6 [2] 6c e6 [2] 53 fa }

  condition:
    any of them
}