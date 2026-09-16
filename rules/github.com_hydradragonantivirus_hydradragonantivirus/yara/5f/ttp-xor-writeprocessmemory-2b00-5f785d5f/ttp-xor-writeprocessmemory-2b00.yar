rule TTP_XOR_WriteProcessMemory_2b00 {
  strings:
    $key_2b00 = { 7c 72 [2] 4e 50 [2] 48 65 [2] 66 65 [2] 59 79 }

  condition:
    any of them
}