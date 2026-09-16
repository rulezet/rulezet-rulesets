rule TTP_XOR_WriteProcessMemory_1517 {
  strings:
    $key_1517 = { 42 65 [2] 70 47 [2] 76 72 [2] 58 72 [2] 67 6e }

  condition:
    any of them
}