rule TTP_XOR_WriteProcessMemory_7932 {
  strings:
    $key_7932 = { 2e 40 [2] 1c 62 [2] 1a 57 [2] 34 57 [2] 0b 4b }

  condition:
    any of them
}