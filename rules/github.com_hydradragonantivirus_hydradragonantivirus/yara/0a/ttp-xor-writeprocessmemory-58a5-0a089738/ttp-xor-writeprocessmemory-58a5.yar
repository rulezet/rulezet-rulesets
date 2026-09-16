rule TTP_XOR_WriteProcessMemory_58a5 {
  strings:
    $key_58a5 = { 0f d7 [2] 3d f5 [2] 3b c0 [2] 15 c0 [2] 2a dc }

  condition:
    any of them
}