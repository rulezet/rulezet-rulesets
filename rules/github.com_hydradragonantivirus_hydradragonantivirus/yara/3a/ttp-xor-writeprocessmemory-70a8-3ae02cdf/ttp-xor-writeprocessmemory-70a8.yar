rule TTP_XOR_WriteProcessMemory_70a8 {
  strings:
    $key_70a8 = { 27 da [2] 15 f8 [2] 13 cd [2] 3d cd [2] 02 d1 }

  condition:
    any of them
}