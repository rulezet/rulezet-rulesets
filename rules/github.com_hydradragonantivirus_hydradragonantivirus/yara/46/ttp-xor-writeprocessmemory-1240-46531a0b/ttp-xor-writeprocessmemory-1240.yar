rule TTP_XOR_WriteProcessMemory_1240 {
  strings:
    $key_1240 = { 45 32 [2] 77 10 [2] 71 25 [2] 5f 25 [2] 60 39 }

  condition:
    any of them
}