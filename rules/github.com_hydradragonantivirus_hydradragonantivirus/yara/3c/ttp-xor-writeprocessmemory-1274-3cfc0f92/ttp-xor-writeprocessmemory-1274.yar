rule TTP_XOR_WriteProcessMemory_1274 {
  strings:
    $key_1274 = { 45 06 [2] 77 24 [2] 71 11 [2] 5f 11 [2] 60 0d }

  condition:
    any of them
}