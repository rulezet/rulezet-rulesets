rule TTP_XOR_WriteProcessMemory_3d00 {
  strings:
    $key_3d00 = { 6a 72 [2] 58 50 [2] 5e 65 [2] 70 65 [2] 4f 79 }

  condition:
    any of them
}