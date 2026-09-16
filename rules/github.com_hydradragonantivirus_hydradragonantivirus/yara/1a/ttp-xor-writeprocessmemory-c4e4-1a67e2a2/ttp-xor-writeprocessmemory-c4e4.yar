rule TTP_XOR_WriteProcessMemory_c4e4 {
  strings:
    $key_c4e4 = { 93 96 [2] a1 b4 [2] a7 81 [2] 89 81 [2] b6 9d }

  condition:
    any of them
}