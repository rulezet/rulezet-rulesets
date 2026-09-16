rule TTP_XOR_WriteProcessMemory_54a8 {
  strings:
    $key_54a8 = { 03 da [2] 31 f8 [2] 37 cd [2] 19 cd [2] 26 d1 }

  condition:
    any of them
}