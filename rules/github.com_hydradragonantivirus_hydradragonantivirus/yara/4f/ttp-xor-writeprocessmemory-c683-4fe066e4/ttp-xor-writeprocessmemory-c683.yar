rule TTP_XOR_WriteProcessMemory_c683 {
  strings:
    $key_c683 = { 91 f1 [2] a3 d3 [2] a5 e6 [2] 8b e6 [2] b4 fa }

  condition:
    any of them
}