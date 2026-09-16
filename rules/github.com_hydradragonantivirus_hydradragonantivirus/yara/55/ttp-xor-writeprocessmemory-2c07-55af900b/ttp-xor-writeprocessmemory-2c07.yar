rule TTP_XOR_WriteProcessMemory_2c07 {
  strings:
    $key_2c07 = { 7b 75 [2] 49 57 [2] 4f 62 [2] 61 62 [2] 5e 7e }

  condition:
    any of them
}