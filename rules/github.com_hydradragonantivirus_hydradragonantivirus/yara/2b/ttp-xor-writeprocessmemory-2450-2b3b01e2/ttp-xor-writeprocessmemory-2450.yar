rule TTP_XOR_WriteProcessMemory_2450 {
  strings:
    $key_2450 = { 73 22 [2] 41 00 [2] 47 35 [2] 69 35 [2] 56 29 }

  condition:
    any of them
}