rule TTP_XOR_WriteProcessMemory_7407 {
  strings:
    $key_7407 = { 23 75 [2] 11 57 [2] 17 62 [2] 39 62 [2] 06 7e }

  condition:
    any of them
}