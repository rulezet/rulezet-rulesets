rule TTP_XOR_WriteProcessMemory_7b22 {
  strings:
    $key_7b22 = { 2c 50 [2] 1e 72 [2] 18 47 [2] 36 47 [2] 09 5b }

  condition:
    any of them
}