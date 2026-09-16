rule TTP_XOR_WriteProcessMemory_2a50 {
  strings:
    $key_2a50 = { 7d 22 [2] 4f 00 [2] 49 35 [2] 67 35 [2] 58 29 }

  condition:
    any of them
}