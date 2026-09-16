rule TTP_XOR_WriteProcessMemory_7931 {
  strings:
    $key_7931 = { 2e 43 [2] 1c 61 [2] 1a 54 [2] 34 54 [2] 0b 48 }

  condition:
    any of them
}