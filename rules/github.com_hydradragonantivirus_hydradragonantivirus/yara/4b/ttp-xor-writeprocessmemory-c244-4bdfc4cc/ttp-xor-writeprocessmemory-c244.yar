rule TTP_XOR_WriteProcessMemory_c244 {
  strings:
    $key_c244 = { 95 36 [2] a7 14 [2] a1 21 [2] 8f 21 [2] b0 3d }

  condition:
    any of them
}