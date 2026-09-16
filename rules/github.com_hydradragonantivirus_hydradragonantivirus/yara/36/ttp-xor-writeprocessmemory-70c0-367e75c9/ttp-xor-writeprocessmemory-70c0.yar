rule TTP_XOR_WriteProcessMemory_70c0 {
  strings:
    $key_70c0 = { 27 b2 [2] 15 90 [2] 13 a5 [2] 3d a5 [2] 02 b9 }

  condition:
    any of them
}