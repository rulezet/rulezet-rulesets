rule TTP_XOR_WriteProcessMemory_3d24 {
  strings:
    $key_3d24 = { 6a 56 [2] 58 74 [2] 5e 41 [2] 70 41 [2] 4f 5d }

  condition:
    any of them
}