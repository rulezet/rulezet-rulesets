rule TTP_XOR_WriteProcessMemory_4565 {
  strings:
    $key_4565 = { 12 17 [2] 20 35 [2] 26 00 [2] 08 00 [2] 37 1c }

  condition:
    any of them
}