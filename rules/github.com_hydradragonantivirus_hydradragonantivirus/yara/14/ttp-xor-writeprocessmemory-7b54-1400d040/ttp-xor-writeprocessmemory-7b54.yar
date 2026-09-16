rule TTP_XOR_WriteProcessMemory_7b54 {
  strings:
    $key_7b54 = { 2c 26 [2] 1e 04 [2] 18 31 [2] 36 31 [2] 09 2d }

  condition:
    any of them
}