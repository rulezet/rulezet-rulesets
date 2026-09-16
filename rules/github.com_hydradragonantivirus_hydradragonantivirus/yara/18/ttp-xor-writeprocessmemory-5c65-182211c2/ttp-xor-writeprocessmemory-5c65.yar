rule TTP_XOR_WriteProcessMemory_5c65 {
  strings:
    $key_5c65 = { 0b 17 [2] 39 35 [2] 3f 00 [2] 11 00 [2] 2e 1c }

  condition:
    any of them
}