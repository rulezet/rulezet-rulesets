rule TTP_XOR_WriteProcessMemory_1b3d {
  strings:
    $key_1b3d = { 4c 4f [2] 7e 6d [2] 78 58 [2] 56 58 [2] 69 44 }

  condition:
    any of them
}