rule TTP_XOR_WriteProcessMemory_07a8 {
  strings:
    $key_07a8 = { 50 da [2] 62 f8 [2] 64 cd [2] 4a cd [2] 75 d1 }

  condition:
    any of them
}