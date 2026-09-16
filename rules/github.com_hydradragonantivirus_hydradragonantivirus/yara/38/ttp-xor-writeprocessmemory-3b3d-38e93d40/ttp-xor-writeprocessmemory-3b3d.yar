rule TTP_XOR_WriteProcessMemory_3b3d {
  strings:
    $key_3b3d = { 6c 4f [2] 5e 6d [2] 58 58 [2] 76 58 [2] 49 44 }

  condition:
    any of them
}