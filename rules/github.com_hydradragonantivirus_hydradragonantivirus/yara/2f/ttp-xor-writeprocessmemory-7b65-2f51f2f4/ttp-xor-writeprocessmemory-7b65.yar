rule TTP_XOR_WriteProcessMemory_7b65 {
  strings:
    $key_7b65 = { 2c 17 [2] 1e 35 [2] 18 00 [2] 36 00 [2] 09 1c }

  condition:
    any of them
}