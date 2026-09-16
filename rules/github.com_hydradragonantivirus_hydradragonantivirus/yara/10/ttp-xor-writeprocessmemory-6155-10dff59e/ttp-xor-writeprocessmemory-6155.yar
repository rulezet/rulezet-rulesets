rule TTP_XOR_WriteProcessMemory_6155 {
  strings:
    $key_6155 = { 36 27 [2] 04 05 [2] 02 30 [2] 2c 30 [2] 13 2c }

  condition:
    any of them
}