rule TTP_XOR_WriteProcessMemory_3d08 {
  strings:
    $key_3d08 = { 6a 7a [2] 58 58 [2] 5e 6d [2] 70 6d [2] 4f 71 }

  condition:
    any of them
}