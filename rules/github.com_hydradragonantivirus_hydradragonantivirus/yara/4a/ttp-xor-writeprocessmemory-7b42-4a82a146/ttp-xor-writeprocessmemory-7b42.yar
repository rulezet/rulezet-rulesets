rule TTP_XOR_WriteProcessMemory_7b42 {
  strings:
    $key_7b42 = { 2c 30 [2] 1e 12 [2] 18 27 [2] 36 27 [2] 09 3b }

  condition:
    any of them
}