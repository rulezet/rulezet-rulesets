rule TTP_XOR_WriteProcessMemory_1858 {
  strings:
    $key_1858 = { 4f 2a [2] 7d 08 [2] 7b 3d [2] 55 3d [2] 6a 21 }

  condition:
    any of them
}