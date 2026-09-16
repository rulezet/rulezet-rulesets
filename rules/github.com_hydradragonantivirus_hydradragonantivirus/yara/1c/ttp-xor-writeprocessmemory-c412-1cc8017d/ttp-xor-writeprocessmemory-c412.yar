rule TTP_XOR_WriteProcessMemory_c412 {
  strings:
    $key_c412 = { 93 60 [2] a1 42 [2] a7 77 [2] 89 77 [2] b6 6b }

  condition:
    any of them
}