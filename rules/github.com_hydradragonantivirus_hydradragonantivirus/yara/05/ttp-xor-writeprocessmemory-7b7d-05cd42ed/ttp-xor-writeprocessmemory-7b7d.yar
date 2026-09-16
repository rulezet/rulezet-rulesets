rule TTP_XOR_WriteProcessMemory_7b7d {
  strings:
    $key_7b7d = { 2c 0f [2] 1e 2d [2] 18 18 [2] 36 18 [2] 09 04 }

  condition:
    any of them
}