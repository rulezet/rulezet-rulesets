rule TTP_XOR_WriteProcessMemory_55a8 {
  strings:
    $key_55a8 = { 02 da [2] 30 f8 [2] 36 cd [2] 18 cd [2] 27 d1 }

  condition:
    any of them
}