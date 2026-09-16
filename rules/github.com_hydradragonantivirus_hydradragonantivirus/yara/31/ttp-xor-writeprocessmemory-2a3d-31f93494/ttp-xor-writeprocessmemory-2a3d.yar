rule TTP_XOR_WriteProcessMemory_2a3d {
  strings:
    $key_2a3d = { 7d 4f [2] 4f 6d [2] 49 58 [2] 67 58 [2] 58 44 }

  condition:
    any of them
}