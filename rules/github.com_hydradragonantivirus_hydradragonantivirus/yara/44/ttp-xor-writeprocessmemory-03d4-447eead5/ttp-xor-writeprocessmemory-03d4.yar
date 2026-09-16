rule TTP_XOR_WriteProcessMemory_03d4 {
  strings:
    $key_03d4 = { 54 a6 [2] 66 84 [2] 60 b1 [2] 4e b1 [2] 71 ad }

  condition:
    any of them
}