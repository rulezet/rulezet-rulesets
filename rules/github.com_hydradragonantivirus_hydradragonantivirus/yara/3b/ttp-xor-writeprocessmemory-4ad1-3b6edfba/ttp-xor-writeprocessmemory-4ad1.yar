rule TTP_XOR_WriteProcessMemory_4ad1 {
  strings:
    $key_4ad1 = { 1d a3 [2] 2f 81 [2] 29 b4 [2] 07 b4 [2] 38 a8 }

  condition:
    any of them
}