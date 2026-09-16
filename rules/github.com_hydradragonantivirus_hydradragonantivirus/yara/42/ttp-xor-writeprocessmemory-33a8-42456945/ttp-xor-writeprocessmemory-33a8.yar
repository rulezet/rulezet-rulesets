rule TTP_XOR_WriteProcessMemory_33a8 {
  strings:
    $key_33a8 = { 64 da [2] 56 f8 [2] 50 cd [2] 7e cd [2] 41 d1 }

  condition:
    any of them
}