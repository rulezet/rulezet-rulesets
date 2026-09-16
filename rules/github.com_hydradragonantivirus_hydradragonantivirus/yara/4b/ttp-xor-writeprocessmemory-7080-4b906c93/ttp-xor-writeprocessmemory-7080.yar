rule TTP_XOR_WriteProcessMemory_7080 {
  strings:
    $key_7080 = { 27 f2 [2] 15 d0 [2] 13 e5 [2] 3d e5 [2] 02 f9 }

  condition:
    any of them
}