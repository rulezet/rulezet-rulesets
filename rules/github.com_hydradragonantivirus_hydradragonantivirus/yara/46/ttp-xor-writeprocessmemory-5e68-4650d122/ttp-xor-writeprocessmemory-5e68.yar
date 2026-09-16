rule TTP_XOR_WriteProcessMemory_5e68 {
  strings:
    $key_5e68 = { 09 1a [2] 3b 38 [2] 3d 0d [2] 13 0d [2] 2c 11 }

  condition:
    any of them
}