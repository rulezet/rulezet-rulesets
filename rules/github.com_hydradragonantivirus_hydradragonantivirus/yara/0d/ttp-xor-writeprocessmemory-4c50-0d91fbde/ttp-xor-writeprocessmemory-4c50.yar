rule TTP_XOR_WriteProcessMemory_4c50 {
  strings:
    $key_4c50 = { 1b 22 [2] 29 00 [2] 2f 35 [2] 01 35 [2] 3e 29 }

  condition:
    any of them
}