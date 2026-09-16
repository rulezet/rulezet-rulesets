rule TTP_XOR_WriteProcessMemory_d1f3 {
  strings:
    $key_d1f3 = { 86 81 [2] b4 a3 [2] b2 96 [2] 9c 96 [2] a3 8a }

  condition:
    any of them
}