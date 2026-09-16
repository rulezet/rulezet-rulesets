rule TTP_XOR_WriteProcessMemory_7b10 {
  strings:
    $key_7b10 = { 2c 62 [2] 1e 40 [2] 18 75 [2] 36 75 [2] 09 69 }

  condition:
    any of them
}