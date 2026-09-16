rule TTP_XOR_WriteProcessMemory_6165 {
  strings:
    $key_6165 = { 36 17 [2] 04 35 [2] 02 00 [2] 2c 00 [2] 13 1c }

  condition:
    any of them
}