rule TTP_XOR_WriteProcessMemory_d3ed {
  strings:
    $key_d3ed = { 84 9f [2] b6 bd [2] b0 88 [2] 9e 88 [2] a1 94 }

  condition:
    any of them
}