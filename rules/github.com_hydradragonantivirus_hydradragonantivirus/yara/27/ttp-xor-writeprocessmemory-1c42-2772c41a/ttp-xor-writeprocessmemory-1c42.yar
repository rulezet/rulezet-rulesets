rule TTP_XOR_WriteProcessMemory_1c42 {
  strings:
    $key_1c42 = { 4b 30 [2] 79 12 [2] 7f 27 [2] 51 27 [2] 6e 3b }

  condition:
    any of them
}