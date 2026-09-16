rule TTP_XOR_WriteProcessMemory_7b48 {
  strings:
    $key_7b48 = { 2c 3a [2] 1e 18 [2] 18 2d [2] 36 2d [2] 09 31 }

  condition:
    any of them
}