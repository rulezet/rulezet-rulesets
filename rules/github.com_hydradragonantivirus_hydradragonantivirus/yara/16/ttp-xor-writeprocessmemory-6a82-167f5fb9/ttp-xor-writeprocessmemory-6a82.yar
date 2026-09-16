rule TTP_XOR_WriteProcessMemory_6a82 {
  strings:
    $key_6a82 = { 3d f0 [2] 0f d2 [2] 09 e7 [2] 27 e7 [2] 18 fb }

  condition:
    any of them
}