rule TTP_XOR_WriteProcessMemory_fab6 {
  strings:
    $key_fab6 = { ad c4 [2] 9f e6 [2] 99 d3 [2] b7 d3 [2] 88 cf }

  condition:
    any of them
}