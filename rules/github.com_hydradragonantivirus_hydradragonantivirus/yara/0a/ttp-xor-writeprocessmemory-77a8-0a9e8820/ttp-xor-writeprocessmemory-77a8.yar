rule TTP_XOR_WriteProcessMemory_77a8 {
  strings:
    $key_77a8 = { 20 da [2] 12 f8 [2] 14 cd [2] 3a cd [2] 05 d1 }

  condition:
    any of them
}