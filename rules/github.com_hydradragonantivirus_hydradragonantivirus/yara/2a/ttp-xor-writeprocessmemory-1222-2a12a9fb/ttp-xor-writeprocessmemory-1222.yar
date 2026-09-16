rule TTP_XOR_WriteProcessMemory_1222 {
  strings:
    $key_1222 = { 45 50 [2] 77 72 [2] 71 47 [2] 5f 47 [2] 60 5b }

  condition:
    any of them
}