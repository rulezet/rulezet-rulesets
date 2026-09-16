rule TTP_XOR_WriteProcessMemory_2c64 {
  strings:
    $key_2c64 = { 7b 16 [2] 49 34 [2] 4f 01 [2] 61 01 [2] 5e 1d }

  condition:
    any of them
}