rule TTP_XOR_WriteProcessMemory_c7f3 {
  strings:
    $key_c7f3 = { 90 81 [2] a2 a3 [2] a4 96 [2] 8a 96 [2] b5 8a }

  condition:
    any of them
}