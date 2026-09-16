rule TTP_XOR_WriteProcessMemory_3370 {
  strings:
    $key_3370 = { 64 02 [2] 56 20 [2] 50 15 [2] 7e 15 [2] 41 09 }

  condition:
    any of them
}