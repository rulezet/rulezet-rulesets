rule TTP_XOR_WriteProcessMemory_7913 {
  strings:
    $key_7913 = { 2e 61 [2] 1c 43 [2] 1a 76 [2] 34 76 [2] 0b 6a }

  condition:
    any of them
}