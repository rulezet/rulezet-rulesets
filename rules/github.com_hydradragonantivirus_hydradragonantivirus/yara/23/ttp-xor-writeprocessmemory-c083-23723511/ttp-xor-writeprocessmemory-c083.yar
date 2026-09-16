rule TTP_XOR_WriteProcessMemory_c083 {
  strings:
    $key_c083 = { 97 f1 [2] a5 d3 [2] a3 e6 [2] 8d e6 [2] b2 fa }

  condition:
    any of them
}