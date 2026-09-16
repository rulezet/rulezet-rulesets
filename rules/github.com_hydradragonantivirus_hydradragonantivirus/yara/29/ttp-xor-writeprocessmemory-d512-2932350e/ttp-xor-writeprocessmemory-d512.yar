rule TTP_XOR_WriteProcessMemory_d512 {
  strings:
    $key_d512 = { 82 60 [2] b0 42 [2] b6 77 [2] 98 77 [2] a7 6b }

  condition:
    any of them
}