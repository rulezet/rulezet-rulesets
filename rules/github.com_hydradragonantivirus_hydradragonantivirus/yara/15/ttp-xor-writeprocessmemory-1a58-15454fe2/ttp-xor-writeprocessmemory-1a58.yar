rule TTP_XOR_WriteProcessMemory_1a58 {
  strings:
    $key_1a58 = { 4d 2a [2] 7f 08 [2] 79 3d [2] 57 3d [2] 68 21 }

  condition:
    any of them
}