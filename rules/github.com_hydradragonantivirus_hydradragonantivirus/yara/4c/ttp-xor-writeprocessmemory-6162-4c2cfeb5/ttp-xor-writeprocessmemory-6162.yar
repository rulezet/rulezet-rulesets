rule TTP_XOR_WriteProcessMemory_6162 {
  strings:
    $key_6162 = { 36 10 [2] 04 32 [2] 02 07 [2] 2c 07 [2] 13 1b }

  condition:
    any of them
}