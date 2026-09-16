rule TTP_XOR_WriteProcessMemory_7950 {
  strings:
    $key_7950 = { 2e 22 [2] 1c 00 [2] 1a 35 [2] 34 35 [2] 0b 29 }

  condition:
    any of them
}