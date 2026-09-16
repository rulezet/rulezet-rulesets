rule TTP_XOR_WriteProcessMemory_7600 {
  strings:
    $key_7600 = { 21 72 [2] 13 50 [2] 15 65 [2] 3b 65 [2] 04 79 }

  condition:
    any of them
}