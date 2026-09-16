rule TTP_XOR_WriteProcessMemory_7465 {
  strings:
    $key_7465 = { 23 17 [2] 11 35 [2] 17 00 [2] 39 00 [2] 06 1c }

  condition:
    any of them
}