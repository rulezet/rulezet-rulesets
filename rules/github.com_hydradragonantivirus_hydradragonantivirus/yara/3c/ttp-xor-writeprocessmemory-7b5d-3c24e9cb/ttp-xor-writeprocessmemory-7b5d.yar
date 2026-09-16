rule TTP_XOR_WriteProcessMemory_7b5d {
  strings:
    $key_7b5d = { 2c 2f [2] 1e 0d [2] 18 38 [2] 36 38 [2] 09 24 }

  condition:
    any of them
}