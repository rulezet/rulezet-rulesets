rule TTP_XOR_WriteProcessMemory_6140 {
  strings:
    $key_6140 = { 36 32 [2] 04 10 [2] 02 25 [2] 2c 25 [2] 13 39 }

  condition:
    any of them
}