rule TTP_XOR_WriteProcessMemory_1214 {
  strings:
    $key_1214 = { 45 66 [2] 77 44 [2] 71 71 [2] 5f 71 [2] 60 6d }

  condition:
    any of them
}