rule TTP_XOR_WriteProcessMemory_c1f3 {
  strings:
    $key_c1f3 = { 96 81 [2] a4 a3 [2] a2 96 [2] 8c 96 [2] b3 8a }

  condition:
    any of them
}