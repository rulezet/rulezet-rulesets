rule TTP_XOR_WriteProcessMemory_5e28 {
  strings:
    $key_5e28 = { 09 5a [2] 3b 78 [2] 3d 4d [2] 13 4d [2] 2c 51 }

  condition:
    any of them
}