rule TTP_XOR_WriteProcessMemory_3d60 {
  strings:
    $key_3d60 = { 6a 12 [2] 58 30 [2] 5e 05 [2] 70 05 [2] 4f 19 }

  condition:
    any of them
}