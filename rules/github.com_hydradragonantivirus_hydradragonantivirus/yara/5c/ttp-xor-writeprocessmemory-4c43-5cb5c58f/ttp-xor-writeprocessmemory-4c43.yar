rule TTP_XOR_WriteProcessMemory_4c43 {
  strings:
    $key_4c43 = { 1b 31 [2] 29 13 [2] 2f 26 [2] 01 26 [2] 3e 3a }

  condition:
    any of them
}