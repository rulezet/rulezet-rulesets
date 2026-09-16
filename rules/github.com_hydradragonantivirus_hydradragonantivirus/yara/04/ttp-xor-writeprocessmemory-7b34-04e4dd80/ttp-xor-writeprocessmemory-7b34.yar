rule TTP_XOR_WriteProcessMemory_7b34 {
  strings:
    $key_7b34 = { 2c 46 [2] 1e 64 [2] 18 51 [2] 36 51 [2] 09 4d }

  condition:
    any of them
}