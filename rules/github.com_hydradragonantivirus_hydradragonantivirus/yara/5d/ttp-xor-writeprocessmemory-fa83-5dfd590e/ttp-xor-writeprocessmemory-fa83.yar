rule TTP_XOR_WriteProcessMemory_fa83 {
  strings:
    $key_fa83 = { ad f1 [2] 9f d3 [2] 99 e6 [2] b7 e6 [2] 88 fa }

  condition:
    any of them
}