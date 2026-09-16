rule TTP_XOR_WriteProcessMemory_7155 {
  strings:
    $key_7155 = { 26 27 [2] 14 05 [2] 12 30 [2] 3c 30 [2] 03 2c }

  condition:
    any of them
}