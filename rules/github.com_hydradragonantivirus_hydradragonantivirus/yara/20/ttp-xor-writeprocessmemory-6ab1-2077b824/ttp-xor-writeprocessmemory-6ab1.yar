rule TTP_XOR_WriteProcessMemory_6ab1 {
  strings:
    $key_6ab1 = { 3d c3 [2] 0f e1 [2] 09 d4 [2] 27 d4 [2] 18 c8 }

  condition:
    any of them
}