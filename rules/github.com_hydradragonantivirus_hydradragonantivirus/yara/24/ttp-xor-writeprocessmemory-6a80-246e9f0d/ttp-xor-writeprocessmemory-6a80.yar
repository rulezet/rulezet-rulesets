rule TTP_XOR_WriteProcessMemory_6a80 {
  strings:
    $key_6a80 = { 3d f2 [2] 0f d0 [2] 09 e5 [2] 27 e5 [2] 18 f9 }

  condition:
    any of them
}