rule TTP_XOR_WriteProcessMemory_3d32 {
  strings:
    $key_3d32 = { 6a 40 [2] 58 62 [2] 5e 57 [2] 70 57 [2] 4f 4b }

  condition:
    any of them
}