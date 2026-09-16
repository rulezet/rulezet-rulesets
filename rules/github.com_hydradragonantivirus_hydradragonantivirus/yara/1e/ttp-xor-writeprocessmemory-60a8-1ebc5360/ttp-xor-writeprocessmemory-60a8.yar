rule TTP_XOR_WriteProcessMemory_60a8 {
  strings:
    $key_60a8 = { 37 da [2] 05 f8 [2] 03 cd [2] 2d cd [2] 12 d1 }

  condition:
    any of them
}