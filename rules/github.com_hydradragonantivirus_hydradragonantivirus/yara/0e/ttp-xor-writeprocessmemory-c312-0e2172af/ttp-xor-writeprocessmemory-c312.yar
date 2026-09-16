rule TTP_XOR_WriteProcessMemory_c312 {
  strings:
    $key_c312 = { 94 60 [2] a6 42 [2] a0 77 [2] 8e 77 [2] b1 6b }

  condition:
    any of them
}