rule TTP_XOR_WriteProcessMemory_7941 {
  strings:
    $key_7941 = { 2e 33 [2] 1c 11 [2] 1a 24 [2] 34 24 [2] 0b 38 }

  condition:
    any of them
}