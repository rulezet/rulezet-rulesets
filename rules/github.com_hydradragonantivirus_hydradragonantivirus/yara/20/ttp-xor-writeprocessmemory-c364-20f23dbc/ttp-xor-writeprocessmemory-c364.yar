rule TTP_XOR_WriteProcessMemory_c364 {
  strings:
    $key_c364 = { 94 16 [2] a6 34 [2] a0 01 [2] 8e 01 [2] b1 1d }

  condition:
    any of them
}