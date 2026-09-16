rule TTP_XOR_WriteProcessMemory_6a97 {
  strings:
    $key_6a97 = { 3d e5 [2] 0f c7 [2] 09 f2 [2] 27 f2 [2] 18 ee }

  condition:
    any of them
}