rule TTP_XOR_WriteProcessMemory_5810 {
  strings:
    $key_5810 = { 0f 62 [2] 3d 40 [2] 3b 75 [2] 15 75 [2] 2a 69 }

  condition:
    any of them
}