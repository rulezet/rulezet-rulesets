rule TTP_XOR_WriteProcessMemory_4f38 {
  strings:
    $key_4f38 = { 18 4a [2] 2a 68 [2] 2c 5d [2] 02 5d [2] 3d 41 }

  condition:
    any of them
}