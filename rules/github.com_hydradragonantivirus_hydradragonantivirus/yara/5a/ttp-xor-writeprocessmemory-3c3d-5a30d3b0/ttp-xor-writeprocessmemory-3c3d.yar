rule TTP_XOR_WriteProcessMemory_3c3d {
  strings:
    $key_3c3d = { 6b 4f [2] 59 6d [2] 5f 58 [2] 71 58 [2] 4e 44 }

  condition:
    any of them
}