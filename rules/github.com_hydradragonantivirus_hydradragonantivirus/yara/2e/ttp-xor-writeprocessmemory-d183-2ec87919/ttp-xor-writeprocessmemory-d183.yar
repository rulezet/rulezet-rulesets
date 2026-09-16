rule TTP_XOR_WriteProcessMemory_d183 {
  strings:
    $key_d183 = { 86 f1 [2] b4 d3 [2] b2 e6 [2] 9c e6 [2] a3 fa }

  condition:
    any of them
}