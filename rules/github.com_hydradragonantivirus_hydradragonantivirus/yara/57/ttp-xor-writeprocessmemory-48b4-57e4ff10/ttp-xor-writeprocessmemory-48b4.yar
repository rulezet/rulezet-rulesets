rule TTP_XOR_WriteProcessMemory_48b4 {
  strings:
    $key_48b4 = { 1f c6 [2] 2d e4 [2] 2b d1 [2] 05 d1 [2] 3a cd }

  condition:
    any of them
}