rule TTP_XOR_WriteProcessMemory_6175 {
  strings:
    $key_6175 = { 36 07 [2] 04 25 [2] 02 10 [2] 2c 10 [2] 13 0c }

  condition:
    any of them
}