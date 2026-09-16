rule TTP_XOR_WriteProcessMemory_5850 {
  strings:
    $key_5850 = { 0f 22 [2] 3d 00 [2] 3b 35 [2] 15 35 [2] 2a 29 }

  condition:
    any of them
}