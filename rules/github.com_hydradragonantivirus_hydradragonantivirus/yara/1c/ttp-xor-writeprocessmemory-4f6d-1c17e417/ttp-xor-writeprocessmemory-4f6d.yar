rule TTP_XOR_WriteProcessMemory_4f6d {
  strings:
    $key_4f6d = { 18 1f [2] 2a 3d [2] 2c 08 [2] 02 08 [2] 3d 14 }

  condition:
    any of them
}