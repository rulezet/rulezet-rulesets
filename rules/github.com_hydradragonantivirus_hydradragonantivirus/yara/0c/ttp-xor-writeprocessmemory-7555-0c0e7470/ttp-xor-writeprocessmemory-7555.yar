rule TTP_XOR_WriteProcessMemory_7555 {
  strings:
    $key_7555 = { 22 27 [2] 10 05 [2] 16 30 [2] 38 30 [2] 07 2c }

  condition:
    any of them
}