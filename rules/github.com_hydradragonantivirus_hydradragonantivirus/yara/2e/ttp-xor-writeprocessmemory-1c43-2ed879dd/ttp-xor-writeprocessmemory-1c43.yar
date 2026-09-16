rule TTP_XOR_WriteProcessMemory_1c43 {
  strings:
    $key_1c43 = { 4b 31 [2] 79 13 [2] 7f 26 [2] 51 26 [2] 6e 3a }

  condition:
    any of them
}