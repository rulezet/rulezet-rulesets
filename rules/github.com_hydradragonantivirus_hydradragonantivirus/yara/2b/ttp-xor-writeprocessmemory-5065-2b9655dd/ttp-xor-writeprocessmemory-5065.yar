rule TTP_XOR_WriteProcessMemory_5065 {
  strings:
    $key_5065 = { 07 17 [2] 35 35 [2] 33 00 [2] 1d 00 [2] 22 1c }

  condition:
    any of them
}