rule TTP_XOR_WriteProcessMemory_1c53 {
  strings:
    $key_1c53 = { 4b 21 [2] 79 03 [2] 7f 36 [2] 51 36 [2] 6e 2a }

  condition:
    any of them
}