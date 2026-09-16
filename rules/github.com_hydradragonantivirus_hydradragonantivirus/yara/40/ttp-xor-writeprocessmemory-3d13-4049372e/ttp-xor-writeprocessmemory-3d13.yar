rule TTP_XOR_WriteProcessMemory_3d13 {
  strings:
    $key_3d13 = { 6a 61 [2] 58 43 [2] 5e 76 [2] 70 76 [2] 4f 6a }

  condition:
    any of them
}