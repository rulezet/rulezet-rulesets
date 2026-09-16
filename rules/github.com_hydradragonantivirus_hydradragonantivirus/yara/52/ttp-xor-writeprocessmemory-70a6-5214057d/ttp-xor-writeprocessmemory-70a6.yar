rule TTP_XOR_WriteProcessMemory_70a6 {
  strings:
    $key_70a6 = { 27 d4 [2] 15 f6 [2] 13 c3 [2] 3d c3 [2] 02 df }

  condition:
    any of them
}