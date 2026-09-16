rule TTP_XOR_WriteProcessMemory_7b97 {
  strings:
    $key_7b97 = { 2c e5 [2] 1e c7 [2] 18 f2 [2] 36 f2 [2] 09 ee }

  condition:
    any of them
}