rule TTP_XOR_WriteProcessMemory_2e58 {
  strings:
    $key_2e58 = { 79 2a [2] 4b 08 [2] 4d 3d [2] 63 3d [2] 5c 21 }

  condition:
    any of them
}