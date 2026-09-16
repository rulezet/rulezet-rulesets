rule TTP_XOR_WriteProcessMemory_fab4 {
  strings:
    $key_fab4 = { ad c6 [2] 9f e4 [2] 99 d1 [2] b7 d1 [2] 88 cd }

  condition:
    any of them
}