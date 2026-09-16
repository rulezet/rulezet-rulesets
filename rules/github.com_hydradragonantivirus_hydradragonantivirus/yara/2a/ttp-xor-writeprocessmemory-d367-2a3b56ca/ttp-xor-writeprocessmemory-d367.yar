rule TTP_XOR_WriteProcessMemory_d367 {
  strings:
    $key_d367 = { 84 15 [2] b6 37 [2] b0 02 [2] 9e 02 [2] a1 1e }

  condition:
    any of them
}