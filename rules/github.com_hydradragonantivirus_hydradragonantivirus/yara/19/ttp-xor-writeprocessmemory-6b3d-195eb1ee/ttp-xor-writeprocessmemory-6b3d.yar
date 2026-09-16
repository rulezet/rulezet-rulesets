rule TTP_XOR_WriteProcessMemory_6b3d {
  strings:
    $key_6b3d = { 3c 4f [2] 0e 6d [2] 08 58 [2] 26 58 [2] 19 44 }

  condition:
    any of them
}