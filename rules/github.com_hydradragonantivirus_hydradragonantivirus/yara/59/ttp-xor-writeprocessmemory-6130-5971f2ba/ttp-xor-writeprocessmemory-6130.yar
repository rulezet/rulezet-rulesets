rule TTP_XOR_WriteProcessMemory_6130 {
  strings:
    $key_6130 = { 36 42 [2] 04 60 [2] 02 55 [2] 2c 55 [2] 13 49 }

  condition:
    any of them
}