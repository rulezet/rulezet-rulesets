rule TTP_XOR_WriteProcessMemory_6170 {
  strings:
    $key_6170 = { 36 02 [2] 04 20 [2] 02 15 [2] 2c 15 [2] 13 09 }

  condition:
    any of them
}