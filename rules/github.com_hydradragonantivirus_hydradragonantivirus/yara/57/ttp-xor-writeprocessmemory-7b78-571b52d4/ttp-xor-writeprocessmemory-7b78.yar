rule TTP_XOR_WriteProcessMemory_7b78 {
  strings:
    $key_7b78 = { 2c 0a [2] 1e 28 [2] 18 1d [2] 36 1d [2] 09 01 }

  condition:
    any of them
}