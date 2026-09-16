rule TTP_XOR_WriteProcessMemory_2b50 {
  strings:
    $key_2b50 = { 7c 22 [2] 4e 00 [2] 48 35 [2] 66 35 [2] 59 29 }

  condition:
    any of them
}