rule TTP_XOR_WriteProcessMemory_61f7 {
  strings:
    $key_61f7 = { 36 85 [2] 04 a7 [2] 02 92 [2] 2c 92 [2] 13 8e }

  condition:
    any of them
}