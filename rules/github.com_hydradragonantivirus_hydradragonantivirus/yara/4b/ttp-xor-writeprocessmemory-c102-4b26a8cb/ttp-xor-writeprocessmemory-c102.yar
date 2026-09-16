rule TTP_XOR_WriteProcessMemory_c102 {
  strings:
    $key_c102 = { 96 70 [2] a4 52 [2] a2 67 [2] 8c 67 [2] b3 7b }

  condition:
    any of them
}