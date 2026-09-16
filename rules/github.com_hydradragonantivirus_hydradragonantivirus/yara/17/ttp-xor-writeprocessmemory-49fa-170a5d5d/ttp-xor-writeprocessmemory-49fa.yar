rule TTP_XOR_WriteProcessMemory_49fa {
  strings:
    $key_49fa = { 1e 88 [2] 2c aa [2] 2a 9f [2] 04 9f [2] 3b 83 }

  condition:
    any of them
}