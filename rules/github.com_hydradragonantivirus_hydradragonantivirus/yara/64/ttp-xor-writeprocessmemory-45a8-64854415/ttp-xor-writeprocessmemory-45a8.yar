rule TTP_XOR_WriteProcessMemory_45a8 {
  strings:
    $key_45a8 = { 12 da [2] 20 f8 [2] 26 cd [2] 08 cd [2] 37 d1 }

  condition:
    any of them
}