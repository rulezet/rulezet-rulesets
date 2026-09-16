rule TTP_XOR_WriteProcessMemory_4941 {
  strings:
    $key_4941 = { 1e 33 [2] 2c 11 [2] 2a 24 [2] 04 24 [2] 3b 38 }

  condition:
    any of them
}