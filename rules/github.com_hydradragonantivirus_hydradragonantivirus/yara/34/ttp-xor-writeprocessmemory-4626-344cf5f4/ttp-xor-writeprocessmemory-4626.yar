rule TTP_XOR_WriteProcessMemory_4626 {
  strings:
    $key_4626 = { 11 54 [2] 23 76 [2] 25 43 [2] 0b 43 [2] 34 5f }

  condition:
    any of them
}