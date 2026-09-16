rule TTP_XOR_WriteProcessMemory_0355 {
  strings:
    $key_0355 = { 54 27 [2] 66 05 [2] 60 30 [2] 4e 30 [2] 71 2c }

  condition:
    any of them
}