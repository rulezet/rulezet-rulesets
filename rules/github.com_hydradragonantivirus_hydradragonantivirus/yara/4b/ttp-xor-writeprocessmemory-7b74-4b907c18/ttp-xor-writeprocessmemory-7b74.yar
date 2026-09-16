rule TTP_XOR_WriteProcessMemory_7b74 {
  strings:
    $key_7b74 = { 2c 06 [2] 1e 24 [2] 18 11 [2] 36 11 [2] 09 0d }

  condition:
    any of them
}