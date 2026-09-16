rule TTP_XOR_WriteProcessMemory_6ab2 {
  strings:
    $key_6ab2 = { 3d c0 [2] 0f e2 [2] 09 d7 [2] 27 d7 [2] 18 cb }

  condition:
    any of them
}