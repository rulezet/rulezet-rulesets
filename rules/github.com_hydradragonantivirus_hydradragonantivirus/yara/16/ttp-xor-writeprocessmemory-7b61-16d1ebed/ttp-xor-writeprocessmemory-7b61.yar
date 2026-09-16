rule TTP_XOR_WriteProcessMemory_7b61 {
  strings:
    $key_7b61 = { 2c 13 [2] 1e 31 [2] 18 04 [2] 36 04 [2] 09 18 }

  condition:
    any of them
}