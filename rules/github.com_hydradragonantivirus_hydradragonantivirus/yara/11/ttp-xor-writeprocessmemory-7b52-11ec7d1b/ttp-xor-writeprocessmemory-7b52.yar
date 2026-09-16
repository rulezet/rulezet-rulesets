rule TTP_XOR_WriteProcessMemory_7b52 {
  strings:
    $key_7b52 = { 2c 20 [2] 1e 02 [2] 18 37 [2] 36 37 [2] 09 2b }

  condition:
    any of them
}