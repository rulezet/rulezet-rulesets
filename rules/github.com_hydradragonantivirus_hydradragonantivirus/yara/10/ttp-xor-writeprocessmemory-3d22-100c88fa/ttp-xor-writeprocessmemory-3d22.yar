rule TTP_XOR_WriteProcessMemory_3d22 {
  strings:
    $key_3d22 = { 6a 50 [2] 58 72 [2] 5e 47 [2] 70 47 [2] 4f 5b }

  condition:
    any of them
}