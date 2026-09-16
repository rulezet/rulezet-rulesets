rule TTP_XOR_WriteProcessMemory_c544 {
  strings:
    $key_c544 = { 92 36 [2] a0 14 [2] a6 21 [2] 88 21 [2] b7 3d }

  condition:
    any of them
}