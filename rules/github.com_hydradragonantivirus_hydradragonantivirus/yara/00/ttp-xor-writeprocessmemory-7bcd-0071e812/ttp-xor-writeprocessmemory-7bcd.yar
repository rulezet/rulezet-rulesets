rule TTP_XOR_WriteProcessMemory_7bcd {
  strings:
    $key_7bcd = { 2c bf [2] 1e 9d [2] 18 a8 [2] 36 a8 [2] 09 b4 }

  condition:
    any of them
}