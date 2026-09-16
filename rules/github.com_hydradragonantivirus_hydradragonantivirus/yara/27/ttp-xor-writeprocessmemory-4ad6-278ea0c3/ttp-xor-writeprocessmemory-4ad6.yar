rule TTP_XOR_WriteProcessMemory_4ad6 {
  strings:
    $key_4ad6 = { 1d a4 [2] 2f 86 [2] 29 b3 [2] 07 b3 [2] 38 af }

  condition:
    any of them
}