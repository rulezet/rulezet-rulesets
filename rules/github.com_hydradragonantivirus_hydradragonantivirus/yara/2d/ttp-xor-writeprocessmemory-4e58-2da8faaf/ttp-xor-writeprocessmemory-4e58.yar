rule TTP_XOR_WriteProcessMemory_4e58 {
  strings:
    $key_4e58 = { 19 2a [2] 2b 08 [2] 2d 3d [2] 03 3d [2] 3c 21 }

  condition:
    any of them
}