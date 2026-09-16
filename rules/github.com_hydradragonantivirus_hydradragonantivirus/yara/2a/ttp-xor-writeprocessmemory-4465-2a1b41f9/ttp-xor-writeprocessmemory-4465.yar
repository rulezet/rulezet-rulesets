rule TTP_XOR_WriteProcessMemory_4465 {
  strings:
    $key_4465 = { 13 17 [2] 21 35 [2] 27 00 [2] 09 00 [2] 36 1c }

  condition:
    any of them
}