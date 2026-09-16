rule TTP_XOR_WriteProcessMemory_5626 {
  strings:
    $key_5626 = { 01 54 [2] 33 76 [2] 35 43 [2] 1b 43 [2] 24 5f }

  condition:
    any of them
}