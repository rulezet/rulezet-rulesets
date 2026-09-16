rule TTP_XOR_WriteProcessMemory_d365 {
  strings:
    $key_d365 = { 84 17 [2] b6 35 [2] b0 00 [2] 9e 00 [2] a1 1c }

  condition:
    any of them
}