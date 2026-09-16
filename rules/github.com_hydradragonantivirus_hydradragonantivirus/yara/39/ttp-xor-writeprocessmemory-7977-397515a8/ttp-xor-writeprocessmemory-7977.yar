rule TTP_XOR_WriteProcessMemory_7977 {
  strings:
    $key_7977 = { 2e 05 [2] 1c 27 [2] 1a 12 [2] 34 12 [2] 0b 0e }

  condition:
    any of them
}