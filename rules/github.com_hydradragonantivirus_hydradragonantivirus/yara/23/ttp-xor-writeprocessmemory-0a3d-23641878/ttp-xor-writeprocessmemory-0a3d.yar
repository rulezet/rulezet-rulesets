rule TTP_XOR_WriteProcessMemory_0a3d {
  strings:
    $key_0a3d = { 5d 4f [2] 6f 6d [2] 69 58 [2] 47 58 [2] 78 44 }

  condition:
    any of them
}