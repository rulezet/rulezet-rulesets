rule TTP_XOR_WriteProcessMemory_e450 {
  strings:
    $key_e450 = { b3 22 [2] 81 00 [2] 87 35 [2] a9 35 [2] 96 29 }

  condition:
    any of them
}