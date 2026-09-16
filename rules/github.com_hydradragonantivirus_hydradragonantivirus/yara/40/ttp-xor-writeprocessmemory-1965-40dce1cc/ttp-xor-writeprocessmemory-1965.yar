rule TTP_XOR_WriteProcessMemory_1965 {
  strings:
    $key_1965 = { 4e 17 [2] 7c 35 [2] 7a 00 [2] 54 00 [2] 6b 1c }

  condition:
    any of them
}