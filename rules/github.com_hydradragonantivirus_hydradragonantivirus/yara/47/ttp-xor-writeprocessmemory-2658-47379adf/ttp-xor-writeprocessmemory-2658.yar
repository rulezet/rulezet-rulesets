rule TTP_XOR_WriteProcessMemory_2658 {
  strings:
    $key_2658 = { 71 2a [2] 43 08 [2] 45 3d [2] 6b 3d [2] 54 21 }

  condition:
    any of them
}