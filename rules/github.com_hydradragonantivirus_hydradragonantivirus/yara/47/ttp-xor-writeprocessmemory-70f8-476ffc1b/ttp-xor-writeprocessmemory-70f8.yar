rule TTP_XOR_WriteProcessMemory_70f8 {
  strings:
    $key_70f8 = { 27 8a [2] 15 a8 [2] 13 9d [2] 3d 9d [2] 02 81 }

  condition:
    any of them
}