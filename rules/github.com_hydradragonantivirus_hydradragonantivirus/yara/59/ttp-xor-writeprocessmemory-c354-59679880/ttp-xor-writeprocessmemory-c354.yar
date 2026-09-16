rule TTP_XOR_WriteProcessMemory_c354 {
  strings:
    $key_c354 = { 94 26 [2] a6 04 [2] a0 31 [2] 8e 31 [2] b1 2d }

  condition:
    any of them
}