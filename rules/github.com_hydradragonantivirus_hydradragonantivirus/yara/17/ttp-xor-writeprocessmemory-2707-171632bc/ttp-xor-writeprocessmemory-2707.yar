rule TTP_XOR_WriteProcessMemory_2707 {
  strings:
    $key_2707 = { 70 75 [2] 42 57 [2] 44 62 [2] 6a 62 [2] 55 7e }

  condition:
    any of them
}