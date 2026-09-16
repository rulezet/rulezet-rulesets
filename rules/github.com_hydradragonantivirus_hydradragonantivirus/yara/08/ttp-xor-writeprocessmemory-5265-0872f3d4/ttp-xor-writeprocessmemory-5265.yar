rule TTP_XOR_WriteProcessMemory_5265 {
  strings:
    $key_5265 = { 05 17 [2] 37 35 [2] 31 00 [2] 1f 00 [2] 20 1c }

  condition:
    any of them
}