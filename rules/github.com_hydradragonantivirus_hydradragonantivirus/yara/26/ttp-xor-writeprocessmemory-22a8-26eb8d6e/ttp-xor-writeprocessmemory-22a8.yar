rule TTP_XOR_WriteProcessMemory_22a8 {
  strings:
    $key_22a8 = { 75 da [2] 47 f8 [2] 41 cd [2] 6f cd [2] 50 d1 }

  condition:
    any of them
}