rule TTP_XOR_WriteProcessMemory_7b23 {
  strings:
    $key_7b23 = { 2c 51 [2] 1e 73 [2] 18 46 [2] 36 46 [2] 09 5a }

  condition:
    any of them
}