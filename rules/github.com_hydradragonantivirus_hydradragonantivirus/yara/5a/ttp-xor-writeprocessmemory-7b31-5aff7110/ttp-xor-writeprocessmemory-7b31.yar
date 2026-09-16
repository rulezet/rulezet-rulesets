rule TTP_XOR_WriteProcessMemory_7b31 {
  strings:
    $key_7b31 = { 2c 43 [2] 1e 61 [2] 18 54 [2] 36 54 [2] 09 48 }

  condition:
    any of them
}