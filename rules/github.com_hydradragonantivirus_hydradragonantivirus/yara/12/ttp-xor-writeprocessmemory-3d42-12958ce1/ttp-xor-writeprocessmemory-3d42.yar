rule TTP_XOR_WriteProcessMemory_3d42 {
  strings:
    $key_3d42 = { 6a 30 [2] 58 12 [2] 5e 27 [2] 70 27 [2] 4f 3b }

  condition:
    any of them
}