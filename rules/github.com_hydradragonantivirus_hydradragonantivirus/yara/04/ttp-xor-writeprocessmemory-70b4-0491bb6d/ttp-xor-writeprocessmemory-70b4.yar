rule TTP_XOR_WriteProcessMemory_70b4 {
  strings:
    $key_70b4 = { 27 c6 [2] 15 e4 [2] 13 d1 [2] 3d d1 [2] 02 cd }

  condition:
    any of them
}