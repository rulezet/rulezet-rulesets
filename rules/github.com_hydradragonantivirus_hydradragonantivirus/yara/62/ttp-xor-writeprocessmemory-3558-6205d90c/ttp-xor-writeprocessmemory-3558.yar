rule TTP_XOR_WriteProcessMemory_3558 {
  strings:
    $key_3558 = { 62 2a [2] 50 08 [2] 56 3d [2] 78 3d [2] 47 21 }

  condition:
    any of them
}