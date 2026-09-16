rule TTP_XOR_WriteProcessMemory_0244 {
  strings:
    $key_0244 = { 55 36 [2] 67 14 [2] 61 21 [2] 4f 21 [2] 70 3d }

  condition:
    any of them
}