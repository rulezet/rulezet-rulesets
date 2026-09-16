rule TTP_XOR_WriteProcessMemory_1511 {
  strings:
    $key_1511 = { 42 63 [2] 70 41 [2] 76 74 [2] 58 74 [2] 67 68 }

  condition:
    any of them
}