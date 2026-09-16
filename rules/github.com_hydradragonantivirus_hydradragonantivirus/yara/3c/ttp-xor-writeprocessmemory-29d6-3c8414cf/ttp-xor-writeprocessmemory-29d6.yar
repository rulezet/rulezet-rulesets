rule TTP_XOR_WriteProcessMemory_29d6 {
  strings:
    $key_29d6 = { 7e a4 [2] 4c 86 [2] 4a b3 [2] 64 b3 [2] 5b af }

  condition:
    any of them
}