rule TTP_XOR_WriteProcessMemory_4c56 {
  strings:
    $key_4c56 = { 1b 24 [2] 29 06 [2] 2f 33 [2] 01 33 [2] 3e 2f }

  condition:
    any of them
}