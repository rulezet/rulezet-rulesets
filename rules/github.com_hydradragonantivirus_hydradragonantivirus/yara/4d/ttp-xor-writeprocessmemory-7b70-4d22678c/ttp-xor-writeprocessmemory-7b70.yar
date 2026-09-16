rule TTP_XOR_WriteProcessMemory_7b70 {
  strings:
    $key_7b70 = { 2c 02 [2] 1e 20 [2] 18 15 [2] 36 15 [2] 09 09 }

  condition:
    any of them
}