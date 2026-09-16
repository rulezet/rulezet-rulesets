rule TTP_XOR_WriteProcessMemory_703d {
  strings:
    $key_703d = { 27 4f [2] 15 6d [2] 13 58 [2] 3d 58 [2] 02 44 }

  condition:
    any of them
}