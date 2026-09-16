rule TTP_XOR_WriteProcessMemory_6107 {
  strings:
    $key_6107 = { 36 75 [2] 04 57 [2] 02 62 [2] 2c 62 [2] 13 7e }

  condition:
    any of them
}