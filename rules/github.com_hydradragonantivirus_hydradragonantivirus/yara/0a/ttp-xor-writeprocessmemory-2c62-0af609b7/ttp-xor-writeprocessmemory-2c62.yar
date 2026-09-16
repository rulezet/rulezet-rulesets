rule TTP_XOR_WriteProcessMemory_2c62 {
  strings:
    $key_2c62 = { 7b 10 [2] 49 32 [2] 4f 07 [2] 61 07 [2] 5e 1b }

  condition:
    any of them
}