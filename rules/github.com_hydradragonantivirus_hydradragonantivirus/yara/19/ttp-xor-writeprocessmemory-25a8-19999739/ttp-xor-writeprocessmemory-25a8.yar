rule TTP_XOR_WriteProcessMemory_25a8 {
  strings:
    $key_25a8 = { 72 da [2] 40 f8 [2] 46 cd [2] 68 cd [2] 57 d1 }

  condition:
    any of them
}