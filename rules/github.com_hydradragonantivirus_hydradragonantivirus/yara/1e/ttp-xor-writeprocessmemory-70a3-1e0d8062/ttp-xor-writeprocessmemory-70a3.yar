rule TTP_XOR_WriteProcessMemory_70a3 {
  strings:
    $key_70a3 = { 27 d1 [2] 15 f3 [2] 13 c6 [2] 3d c6 [2] 02 da }

  condition:
    any of them
}