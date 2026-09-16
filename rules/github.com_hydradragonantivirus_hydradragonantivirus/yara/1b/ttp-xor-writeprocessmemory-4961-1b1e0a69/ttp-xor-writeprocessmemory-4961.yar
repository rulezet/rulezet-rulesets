rule TTP_XOR_WriteProcessMemory_4961 {
  strings:
    $key_4961 = { 1e 13 [2] 2c 31 [2] 2a 04 [2] 04 04 [2] 3b 18 }

  condition:
    any of them
}