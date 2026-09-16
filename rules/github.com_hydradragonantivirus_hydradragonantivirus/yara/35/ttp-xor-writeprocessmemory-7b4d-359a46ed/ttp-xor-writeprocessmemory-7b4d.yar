rule TTP_XOR_WriteProcessMemory_7b4d {
  strings:
    $key_7b4d = { 2c 3f [2] 1e 1d [2] 18 28 [2] 36 28 [2] 09 34 }

  condition:
    any of them
}