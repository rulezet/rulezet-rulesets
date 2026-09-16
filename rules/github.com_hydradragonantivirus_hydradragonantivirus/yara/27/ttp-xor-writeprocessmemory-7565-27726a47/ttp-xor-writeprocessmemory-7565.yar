rule TTP_XOR_WriteProcessMemory_7565 {
  strings:
    $key_7565 = { 22 17 [2] 10 35 [2] 16 00 [2] 38 00 [2] 07 1c }

  condition:
    any of them
}