rule TTP_XOR_WriteProcessMemory_70e7 {
  strings:
    $key_70e7 = { 27 95 [2] 15 b7 [2] 13 82 [2] 3d 82 [2] 02 9e }

  condition:
    any of them
}