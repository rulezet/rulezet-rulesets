rule TTP_XOR_WriteProcessMemory_6a96 {
  strings:
    $key_6a96 = { 3d e4 [2] 0f c6 [2] 09 f3 [2] 27 f3 [2] 18 ef }

  condition:
    any of them
}