rule TTP_XOR_WriteProcessMemory_c535 {
  strings:
    $key_c535 = { 92 47 [2] a0 65 [2] a6 50 [2] 88 50 [2] b7 4c }

  condition:
    any of them
}