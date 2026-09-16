rule TTP_XOR_WriteProcessMemory_d544 {
  strings:
    $key_d544 = { 82 36 [2] b0 14 [2] b6 21 [2] 98 21 [2] a7 3d }

  condition:
    any of them
}