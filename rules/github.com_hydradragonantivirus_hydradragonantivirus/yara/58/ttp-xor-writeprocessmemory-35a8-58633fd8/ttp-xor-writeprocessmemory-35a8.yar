rule TTP_XOR_WriteProcessMemory_35a8 {
  strings:
    $key_35a8 = { 62 da [2] 50 f8 [2] 56 cd [2] 78 cd [2] 47 d1 }

  condition:
    any of them
}