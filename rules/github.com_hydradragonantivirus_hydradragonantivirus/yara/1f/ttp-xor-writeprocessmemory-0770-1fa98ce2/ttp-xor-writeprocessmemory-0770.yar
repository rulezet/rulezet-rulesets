rule TTP_XOR_WriteProcessMemory_0770 {
  strings:
    $key_0770 = { 50 02 [2] 62 20 [2] 64 15 [2] 4a 15 [2] 75 09 }

  condition:
    any of them
}