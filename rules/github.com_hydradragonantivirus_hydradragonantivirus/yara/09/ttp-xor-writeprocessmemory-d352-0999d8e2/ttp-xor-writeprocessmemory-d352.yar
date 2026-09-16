rule TTP_XOR_WriteProcessMemory_d352 {
  strings:
    $key_d352 = { 84 20 [2] b6 02 [2] b0 37 [2] 9e 37 [2] a1 2b }

  condition:
    any of them
}