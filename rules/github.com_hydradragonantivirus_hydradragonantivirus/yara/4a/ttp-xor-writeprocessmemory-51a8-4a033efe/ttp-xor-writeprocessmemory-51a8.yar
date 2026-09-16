rule TTP_XOR_WriteProcessMemory_51a8 {
  strings:
    $key_51a8 = { 06 da [2] 34 f8 [2] 32 cd [2] 1c cd [2] 23 d1 }

  condition:
    any of them
}