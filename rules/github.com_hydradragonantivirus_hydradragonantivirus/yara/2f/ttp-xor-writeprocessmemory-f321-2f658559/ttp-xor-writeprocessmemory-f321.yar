rule TTP_XOR_WriteProcessMemory_f321 {
  strings:
    $key_f321 = { a4 53 [2] 96 71 [2] 90 44 [2] be 44 [2] 81 58 }

  condition:
    any of them
}