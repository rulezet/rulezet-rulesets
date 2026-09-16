rule TTP_XOR_WriteProcessMemory_70f0 {
  strings:
    $key_70f0 = { 27 82 [2] 15 a0 [2] 13 95 [2] 3d 95 [2] 02 89 }

  condition:
    any of them
}