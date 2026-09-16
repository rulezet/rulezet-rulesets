rule TTP_XOR_WriteProcessMemory_2753 {
  strings:
    $key_2753 = { 70 21 [2] 42 03 [2] 44 36 [2] 6a 36 [2] 55 2a }

  condition:
    any of them
}