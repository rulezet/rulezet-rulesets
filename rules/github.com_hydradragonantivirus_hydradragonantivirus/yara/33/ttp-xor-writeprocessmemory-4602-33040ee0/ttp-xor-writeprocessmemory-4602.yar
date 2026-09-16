rule TTP_XOR_WriteProcessMemory_4602 {
  strings:
    $key_4602 = { 11 70 [2] 23 52 [2] 25 67 [2] 0b 67 [2] 34 7b }

  condition:
    any of them
}