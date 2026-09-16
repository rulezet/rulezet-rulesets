rule TTP_XOR_WriteProcessMemory_d305 {
  strings:
    $key_d305 = { 84 77 [2] b6 55 [2] b0 60 [2] 9e 60 [2] a1 7c }

  condition:
    any of them
}