rule TTP_XOR_WriteProcessMemory_0e55 {
  strings:
    $key_0e55 = { 59 27 [2] 6b 05 [2] 6d 30 [2] 43 30 [2] 7c 2c }

  condition:
    any of them
}