rule TTP_XOR_WriteProcessMemory_31a8 {
  strings:
    $key_31a8 = { 66 da [2] 54 f8 [2] 52 cd [2] 7c cd [2] 43 d1 }

  condition:
    any of them
}