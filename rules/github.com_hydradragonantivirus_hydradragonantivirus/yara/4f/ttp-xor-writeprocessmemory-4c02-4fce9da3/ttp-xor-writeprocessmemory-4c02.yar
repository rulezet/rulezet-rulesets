rule TTP_XOR_WriteProcessMemory_4c02 {
  strings:
    $key_4c02 = { 1b 70 [2] 29 52 [2] 2f 67 [2] 01 67 [2] 3e 7b }

  condition:
    any of them
}