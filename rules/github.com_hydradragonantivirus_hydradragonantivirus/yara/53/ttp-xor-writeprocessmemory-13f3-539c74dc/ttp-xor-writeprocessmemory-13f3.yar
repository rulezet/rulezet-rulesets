rule TTP_XOR_WriteProcessMemory_13f3 {
  strings:
    $key_13f3 = { 44 81 [2] 76 a3 [2] 70 96 [2] 5e 96 [2] 61 8a }

  condition:
    any of them
}