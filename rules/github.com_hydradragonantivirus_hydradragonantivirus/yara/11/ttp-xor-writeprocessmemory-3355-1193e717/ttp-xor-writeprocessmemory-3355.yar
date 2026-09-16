rule TTP_XOR_WriteProcessMemory_3355 {
  strings:
    $key_3355 = { 64 27 [2] 56 05 [2] 50 30 [2] 7e 30 [2] 41 2c }

  condition:
    any of them
}