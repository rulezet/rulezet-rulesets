rule TTP_XOR_WriteProcessMemory_4ac1 {
  strings:
    $key_4ac1 = { 1d b3 [2] 2f 91 [2] 29 a4 [2] 07 a4 [2] 38 b8 }

  condition:
    any of them
}