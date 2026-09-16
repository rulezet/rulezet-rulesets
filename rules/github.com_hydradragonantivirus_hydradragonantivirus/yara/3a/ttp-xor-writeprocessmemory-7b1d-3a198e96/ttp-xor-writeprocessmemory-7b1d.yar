rule TTP_XOR_WriteProcessMemory_7b1d {
  strings:
    $key_7b1d = { 2c 6f [2] 1e 4d [2] 18 78 [2] 36 78 [2] 09 64 }

  condition:
    any of them
}