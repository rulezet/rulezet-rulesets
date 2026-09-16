rule TTP_XOR_WriteProcessMemory_70f7 {
  strings:
    $key_70f7 = { 27 85 [2] 15 a7 [2] 13 92 [2] 3d 92 [2] 02 8e }

  condition:
    any of them
}