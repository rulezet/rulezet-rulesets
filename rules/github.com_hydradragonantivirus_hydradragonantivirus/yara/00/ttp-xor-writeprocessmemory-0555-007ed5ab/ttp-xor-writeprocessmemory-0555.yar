rule TTP_XOR_WriteProcessMemory_0555 {
  strings:
    $key_0555 = { 52 27 [2] 60 05 [2] 66 30 [2] 48 30 [2] 77 2c }

  condition:
    any of them
}