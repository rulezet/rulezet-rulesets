rule TTP_XOR_WriteProcessMemory_2655 {
  strings:
    $key_2655 = { 71 27 [2] 43 05 [2] 45 30 [2] 6b 30 [2] 54 2c }

  condition:
    any of them
}