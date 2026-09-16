rule TTP_XOR_WriteProcessMemory_71a8 {
  strings:
    $key_71a8 = { 26 da [2] 14 f8 [2] 12 cd [2] 3c cd [2] 03 d1 }

  condition:
    any of them
}