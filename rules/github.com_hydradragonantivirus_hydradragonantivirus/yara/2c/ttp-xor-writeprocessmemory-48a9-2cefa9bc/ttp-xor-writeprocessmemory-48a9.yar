rule TTP_XOR_WriteProcessMemory_48a9 {
  strings:
    $key_48a9 = { 1f db [2] 2d f9 [2] 2b cc [2] 05 cc [2] 3a d0 }

  condition:
    any of them
}