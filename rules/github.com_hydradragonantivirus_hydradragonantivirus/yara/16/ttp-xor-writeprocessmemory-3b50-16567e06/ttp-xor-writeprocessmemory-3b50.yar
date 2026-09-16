rule TTP_XOR_WriteProcessMemory_3b50 {
  strings:
    $key_3b50 = { 6c 22 [2] 5e 00 [2] 58 35 [2] 76 35 [2] 49 29 }

  condition:
    any of them
}