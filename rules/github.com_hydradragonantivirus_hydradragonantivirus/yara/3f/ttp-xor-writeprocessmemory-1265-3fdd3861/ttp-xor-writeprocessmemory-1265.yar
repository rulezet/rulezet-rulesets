rule TTP_XOR_WriteProcessMemory_1265 {
  strings:
    $key_1265 = { 45 17 [2] 77 35 [2] 71 00 [2] 5f 00 [2] 60 1c }

  condition:
    any of them
}