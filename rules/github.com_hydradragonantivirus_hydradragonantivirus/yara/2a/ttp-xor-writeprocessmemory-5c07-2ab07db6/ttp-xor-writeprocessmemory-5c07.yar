rule TTP_XOR_WriteProcessMemory_5c07 {
  strings:
    $key_5c07 = { 0b 75 [2] 39 57 [2] 3f 62 [2] 11 62 [2] 2e 7e }

  condition:
    any of them
}