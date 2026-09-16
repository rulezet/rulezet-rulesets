rule TTP_XOR_WriteProcessMemory_5e0d {
  strings:
    $key_5e0d = { 09 7f [2] 3b 5d [2] 3d 68 [2] 13 68 [2] 2c 74 }

  condition:
    any of them
}