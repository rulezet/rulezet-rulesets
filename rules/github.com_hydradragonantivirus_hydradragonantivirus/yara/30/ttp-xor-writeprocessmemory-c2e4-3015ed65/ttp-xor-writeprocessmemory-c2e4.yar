rule TTP_XOR_WriteProcessMemory_c2e4 {
  strings:
    $key_c2e4 = { 95 96 [2] a7 b4 [2] a1 81 [2] 8f 81 [2] b0 9d }

  condition:
    any of them
}