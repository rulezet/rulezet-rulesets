rule TTP_XOR_WriteProcessMemory_03d0 {
  strings:
    $key_03d0 = { 54 a2 [2] 66 80 [2] 60 b5 [2] 4e b5 [2] 71 a9 }

  condition:
    any of them
}