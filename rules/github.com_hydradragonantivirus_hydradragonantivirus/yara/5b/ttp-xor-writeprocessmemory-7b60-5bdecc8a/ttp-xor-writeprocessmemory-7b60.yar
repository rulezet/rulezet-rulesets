rule TTP_XOR_WriteProcessMemory_7b60 {
  strings:
    $key_7b60 = { 2c 12 [2] 1e 30 [2] 18 05 [2] 36 05 [2] 09 19 }

  condition:
    any of them
}