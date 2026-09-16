rule TTP_XOR_WriteProcessMemory_1241 {
  strings:
    $key_1241 = { 45 33 [2] 77 11 [2] 71 24 [2] 5f 24 [2] 60 38 }

  condition:
    any of them
}