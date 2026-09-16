rule TTP_XOR_WriteProcessMemory_7b18 {
  strings:
    $key_7b18 = { 2c 6a [2] 1e 48 [2] 18 7d [2] 36 7d [2] 09 61 }

  condition:
    any of them
}