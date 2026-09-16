rule TTP_XOR_WriteProcessMemory_6ac1 {
  strings:
    $key_6ac1 = { 3d b3 [2] 0f 91 [2] 09 a4 [2] 27 a4 [2] 18 b8 }

  condition:
    any of them
}