rule TTP_XOR_WriteProcessMemory_70c1 {
  strings:
    $key_70c1 = { 27 b3 [2] 15 91 [2] 13 a4 [2] 3d a4 [2] 02 b8 }

  condition:
    any of them
}