rule TTP_XOR_WriteProcessMemory_4370 {
  strings:
    $key_4370 = { 14 02 [2] 26 20 [2] 20 15 [2] 0e 15 [2] 31 09 }

  condition:
    any of them
}