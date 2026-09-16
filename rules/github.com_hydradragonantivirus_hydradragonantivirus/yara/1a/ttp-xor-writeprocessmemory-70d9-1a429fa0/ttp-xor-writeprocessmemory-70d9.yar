rule TTP_XOR_WriteProcessMemory_70d9 {
  strings:
    $key_70d9 = { 27 ab [2] 15 89 [2] 13 bc [2] 3d bc [2] 02 a0 }

  condition:
    any of them
}