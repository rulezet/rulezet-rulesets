rule TTP_XOR_WriteProcessMemory_1207 {
  strings:
    $key_1207 = { 45 75 [2] 77 57 [2] 71 62 [2] 5f 62 [2] 60 7e }

  condition:
    any of them
}