rule TTP_XOR_WriteProcessMemory_2f3d {
  strings:
    $key_2f3d = { 78 4f [2] 4a 6d [2] 4c 58 [2] 62 58 [2] 5d 44 }

  condition:
    any of them
}