rule TTP_XOR_WriteProcessMemory_5e38 {
  strings:
    $key_5e38 = { 09 4a [2] 3b 68 [2] 3d 5d [2] 13 5d [2] 2c 41 }

  condition:
    any of them
}