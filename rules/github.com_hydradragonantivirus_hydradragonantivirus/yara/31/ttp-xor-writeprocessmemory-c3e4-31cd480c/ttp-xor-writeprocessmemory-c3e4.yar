rule TTP_XOR_WriteProcessMemory_c3e4 {
  strings:
    $key_c3e4 = { 94 96 [2] a6 b4 [2] a0 81 [2] 8e 81 [2] b1 9d }

  condition:
    any of them
}