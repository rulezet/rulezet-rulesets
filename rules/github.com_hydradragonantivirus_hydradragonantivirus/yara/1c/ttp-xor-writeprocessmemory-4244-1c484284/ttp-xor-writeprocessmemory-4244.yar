rule TTP_XOR_WriteProcessMemory_4244 {
  strings:
    $key_4244 = { 15 36 [2] 27 14 [2] 21 21 [2] 0f 21 [2] 30 3d }

  condition:
    any of them
}