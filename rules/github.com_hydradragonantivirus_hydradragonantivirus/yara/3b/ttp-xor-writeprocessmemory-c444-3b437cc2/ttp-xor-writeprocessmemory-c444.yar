rule TTP_XOR_WriteProcessMemory_c444 {
  strings:
    $key_c444 = { 93 36 [2] a1 14 [2] a7 21 [2] 89 21 [2] b6 3d }

  condition:
    any of them
}