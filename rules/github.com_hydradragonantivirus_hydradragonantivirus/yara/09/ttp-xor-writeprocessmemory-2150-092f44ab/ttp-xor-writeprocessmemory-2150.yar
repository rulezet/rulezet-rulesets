rule TTP_XOR_WriteProcessMemory_2150 {
  strings:
    $key_2150 = { 76 22 [2] 44 00 [2] 42 35 [2] 6c 35 [2] 53 29 }

  condition:
    any of them
}