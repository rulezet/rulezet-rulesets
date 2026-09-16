rule TTP_XOR_WriteProcessMemory_1d07 {
  strings:
    $key_1d07 = { 4a 75 [2] 78 57 [2] 7e 62 [2] 50 62 [2] 6f 7e }

  condition:
    any of them
}