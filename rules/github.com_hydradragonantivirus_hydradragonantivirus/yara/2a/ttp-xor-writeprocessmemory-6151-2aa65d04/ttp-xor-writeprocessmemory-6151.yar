rule TTP_XOR_WriteProcessMemory_6151 {
  strings:
    $key_6151 = { 36 23 [2] 04 01 [2] 02 34 [2] 2c 34 [2] 13 28 }

  condition:
    any of them
}