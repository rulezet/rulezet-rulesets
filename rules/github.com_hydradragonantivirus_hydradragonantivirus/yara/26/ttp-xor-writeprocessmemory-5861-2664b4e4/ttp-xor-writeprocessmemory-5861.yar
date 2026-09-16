rule TTP_XOR_WriteProcessMemory_5861 {
  strings:
    $key_5861 = { 0f 13 [2] 3d 31 [2] 3b 04 [2] 15 04 [2] 2a 18 }

  condition:
    any of them
}