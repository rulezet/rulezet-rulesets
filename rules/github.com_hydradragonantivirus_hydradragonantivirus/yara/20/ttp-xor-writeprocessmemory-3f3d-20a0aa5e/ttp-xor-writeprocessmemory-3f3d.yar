rule TTP_XOR_WriteProcessMemory_3f3d {
  strings:
    $key_3f3d = { 68 4f [2] 5a 6d [2] 5c 58 [2] 72 58 [2] 4d 44 }

  condition:
    any of them
}