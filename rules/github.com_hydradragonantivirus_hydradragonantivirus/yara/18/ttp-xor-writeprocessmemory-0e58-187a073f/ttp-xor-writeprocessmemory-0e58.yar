rule TTP_XOR_WriteProcessMemory_0e58 {
  strings:
    $key_0e58 = { 59 2a [2] 6b 08 [2] 6d 3d [2] 43 3d [2] 7c 21 }

  condition:
    any of them
}