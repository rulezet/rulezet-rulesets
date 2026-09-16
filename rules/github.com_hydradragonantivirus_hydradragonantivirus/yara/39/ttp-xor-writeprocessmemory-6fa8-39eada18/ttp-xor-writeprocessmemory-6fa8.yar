rule TTP_XOR_WriteProcessMemory_6fa8 {
  strings:
    $key_6fa8 = { 38 da [2] 0a f8 [2] 0c cd [2] 22 cd [2] 1d d1 }

  condition:
    any of them
}