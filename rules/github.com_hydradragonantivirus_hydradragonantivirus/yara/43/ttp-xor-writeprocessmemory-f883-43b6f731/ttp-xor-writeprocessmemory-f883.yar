rule TTP_XOR_WriteProcessMemory_f883 {
  strings:
    $key_f883 = { af f1 [2] 9d d3 [2] 9b e6 [2] b5 e6 [2] 8a fa }

  condition:
    any of them
}