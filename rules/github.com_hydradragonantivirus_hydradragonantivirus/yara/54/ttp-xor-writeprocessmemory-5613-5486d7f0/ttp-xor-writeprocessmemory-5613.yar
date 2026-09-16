rule TTP_XOR_WriteProcessMemory_5613 {
  strings:
    $key_5613 = { 01 61 [2] 33 43 [2] 35 76 [2] 1b 76 [2] 24 6a }

  condition:
    any of them
}