rule TTP_XOR_WriteProcessMemory_6243 {
  strings:
    $key_6243 = { 35 31 [2] 07 13 [2] 01 26 [2] 2f 26 [2] 10 3a }

  condition:
    any of them
}