rule TTP_XOR_WriteProcessMemory_c127 {
  strings:
    $key_c127 = { 96 55 [2] a4 77 [2] a2 42 [2] 8c 42 [2] b3 5e }

  condition:
    any of them
}