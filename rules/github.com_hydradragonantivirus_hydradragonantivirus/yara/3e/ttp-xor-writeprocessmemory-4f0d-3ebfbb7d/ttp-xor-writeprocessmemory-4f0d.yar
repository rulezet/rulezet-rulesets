rule TTP_XOR_WriteProcessMemory_4f0d {
  strings:
    $key_4f0d = { 18 7f [2] 2a 5d [2] 2c 68 [2] 02 68 [2] 3d 74 }

  condition:
    any of them
}