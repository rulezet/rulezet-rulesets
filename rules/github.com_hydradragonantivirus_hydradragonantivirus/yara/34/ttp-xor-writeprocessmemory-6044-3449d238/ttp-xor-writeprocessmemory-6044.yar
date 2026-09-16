rule TTP_XOR_WriteProcessMemory_6044 {
  strings:
    $key_6044 = { 37 36 [2] 05 14 [2] 03 21 [2] 2d 21 [2] 12 3d }

  condition:
    any of them
}