rule TTP_XOR_WriteProcessMemory_3fa8 {
  strings:
    $key_3fa8 = { 68 da [2] 5a f8 [2] 5c cd [2] 72 cd [2] 4d d1 }

  condition:
    any of them
}