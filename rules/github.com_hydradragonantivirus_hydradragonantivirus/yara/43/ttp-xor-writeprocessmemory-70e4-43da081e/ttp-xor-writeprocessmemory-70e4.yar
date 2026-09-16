rule TTP_XOR_WriteProcessMemory_70e4 {
  strings:
    $key_70e4 = { 27 96 [2] 15 b4 [2] 13 81 [2] 3d 81 [2] 02 9d }

  condition:
    any of them
}