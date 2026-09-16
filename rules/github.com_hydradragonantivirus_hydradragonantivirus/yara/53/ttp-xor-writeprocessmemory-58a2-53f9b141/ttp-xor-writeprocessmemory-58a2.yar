rule TTP_XOR_WriteProcessMemory_58a2 {
  strings:
    $key_58a2 = { 0f d0 [2] 3d f2 [2] 3b c7 [2] 15 c7 [2] 2a db }

  condition:
    any of them
}