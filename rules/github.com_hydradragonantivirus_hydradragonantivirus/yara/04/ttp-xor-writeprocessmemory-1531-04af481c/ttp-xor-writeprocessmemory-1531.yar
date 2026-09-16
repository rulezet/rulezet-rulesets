rule TTP_XOR_WriteProcessMemory_1531 {
  strings:
    $key_1531 = { 42 43 [2] 70 61 [2] 76 54 [2] 58 54 [2] 67 48 }

  condition:
    any of them
}