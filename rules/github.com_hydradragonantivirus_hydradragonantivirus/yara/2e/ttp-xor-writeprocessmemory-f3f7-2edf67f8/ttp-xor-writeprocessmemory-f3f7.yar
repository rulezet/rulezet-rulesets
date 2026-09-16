rule TTP_XOR_WriteProcessMemory_f3f7 {
  strings:
    $key_f3f7 = { a4 85 [2] 96 a7 [2] 90 92 [2] be 92 [2] 81 8e }

  condition:
    any of them
}