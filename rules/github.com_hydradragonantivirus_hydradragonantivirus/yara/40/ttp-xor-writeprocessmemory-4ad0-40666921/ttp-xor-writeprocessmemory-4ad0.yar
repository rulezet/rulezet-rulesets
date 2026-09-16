rule TTP_XOR_WriteProcessMemory_4ad0 {
  strings:
    $key_4ad0 = { 1d a2 [2] 2f 80 [2] 29 b5 [2] 07 b5 [2] 38 a9 }

  condition:
    any of them
}