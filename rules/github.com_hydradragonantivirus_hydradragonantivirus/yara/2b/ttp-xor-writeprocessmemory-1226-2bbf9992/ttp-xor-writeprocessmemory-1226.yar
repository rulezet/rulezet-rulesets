rule TTP_XOR_WriteProcessMemory_1226 {
  strings:
    $key_1226 = { 45 54 [2] 77 76 [2] 71 43 [2] 5f 43 [2] 60 5f }

  condition:
    any of them
}