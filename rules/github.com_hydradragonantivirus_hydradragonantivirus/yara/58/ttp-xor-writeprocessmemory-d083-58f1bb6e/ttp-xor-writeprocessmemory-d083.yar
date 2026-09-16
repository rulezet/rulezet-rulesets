rule TTP_XOR_WriteProcessMemory_d083 {
  strings:
    $key_d083 = { 87 f1 [2] b5 d3 [2] b3 e6 [2] 9d e6 [2] a2 fa }

  condition:
    any of them
}