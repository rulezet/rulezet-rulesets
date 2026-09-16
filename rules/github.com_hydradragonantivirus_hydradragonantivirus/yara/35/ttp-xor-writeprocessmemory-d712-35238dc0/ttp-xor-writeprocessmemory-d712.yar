rule TTP_XOR_WriteProcessMemory_d712 {
  strings:
    $key_d712 = { 80 60 [2] b2 42 [2] b4 77 [2] 9a 77 [2] a5 6b }

  condition:
    any of them
}