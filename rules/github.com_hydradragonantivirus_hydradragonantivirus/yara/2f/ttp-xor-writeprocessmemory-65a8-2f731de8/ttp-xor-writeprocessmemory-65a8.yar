rule TTP_XOR_WriteProcessMemory_65a8 {
  strings:
    $key_65a8 = { 32 da [2] 00 f8 [2] 06 cd [2] 28 cd [2] 17 d1 }

  condition:
    any of them
}