rule TTP_XOR_WriteProcessMemory_3d65 {
  strings:
    $key_3d65 = { 6a 17 [2] 58 35 [2] 5e 00 [2] 70 00 [2] 4f 1c }

  condition:
    any of them
}