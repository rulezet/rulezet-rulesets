rule TTP_XOR_WriteProcessMemory_7530 {
  strings:
    $key_7530 = { 22 42 [2] 10 60 [2] 16 55 [2] 38 55 [2] 07 49 }

  condition:
    any of them
}